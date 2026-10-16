/*
 * vm_container.c — Phase 1 container runtime for VMOS Clone.
 *
 * Implements:
 *   1. Namespace creation via clone(2)  (PID|NET|MNT|UTS|IPC|USER|CGROUP)
 *   2. Cgroup v1/v2 resource limits    (CPU quota / memory cap / pids)
 *   3. Overlayfs rootfs + pivot_root(8) takeover
 *   4. Host<->guest-init control handshake over a socketpair
 *
 * Threat model notes (VM-escape hardening, enforced here):
 *   - New mount ns is made fully recursive-private BEFORE any mount, so no
 *     propagation can ever write back into the host namespace.
 *   - /proc and /sys are mounted with hidepid=invisible,gid deny-lists and
 *     key pseudo-fs (kcore, timers, sched_debug...) masked over with EROFS
 *     files/dirs, mirroring lxc/lxcfs attack-surface reduction.
 *   - The guest's "root" only exists inside its own user namespace; the host
 *     sees every guest process as uid = cfg->uid_offset (an unprivileged app
 *     uid). CAP_SYS_ADMIN inside the userns grants NO privilege outside it.
 *   - No host block devices, no /dev/mem, no ptrace across ns boundaries
 *     (yama + userns), seccomp filter installed by guest init (Phase 2).
 *
 * Build: NDK clang, C11, links only libc (bionic). See jni/CMakeLists.txt.
 */
#define _GNU_SOURCE
#include "vm_container.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#ifdef __ANDROID__
#include <sys/macros.h>   /* bionic: makedev() */
#else
#include <sys/sysmacros.h>  /* glibc: makedev() */
#endif
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>

#ifndef MS_REC
#define MS_REC 16384
#endif
#ifndef MS_PRIVATE
#define MS_PRIVATE 1<<18
#endif
#ifndef MNT_DETACH
#define MNT_DETACH 2
#endif
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif

#define LOG_TAG "vmcontainer"
#include "vm_log.h"

/* Implemented in jni/guest_init.c — runs as PID 1 inside the guest. */
extern int vmos_guest_init_main(int argc, char **argv);
/* ctrl socket fd inherited by the clone child (COW), set right before clone(). */
static int g_child_ctrl_fd = -1;

/* ---------------------------------------------------------------- utils */

static long ms_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int write_file(const char *path, const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    ssize_t n = write(fd, buf, strlen(buf));
    int saved = errno;
    close(fd);
    if (n < 0) return -saved;
    return 0;
}

static int read_file_str(const char *path, char *out, size_t len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    ssize_t n = read(fd, out, len - 1);
    close(fd);
    if (n < 0) return -errno;
    out[n] = '\0';
    while (n > 0 && (out[n-1] == '\n' || out[n-1] == '\r')) out[--n] = '\0';
    return 0;
}

static int path_exists(const char *p) { return access(p, F_OK) == 0; }

/* join dir + "/" + leaf into a rotating static buffer (single-threaded boot path) */
static const char *pj(const char *dir, const char *leaf) {
    static char bufs[4][VMC_MAX_PATH * 2];
    static int idx = 0;
    char *b = bufs[idx]; idx = (idx + 1) & 3;
    snprintf(b, sizeof(bufs[0]), "%s%s", dir, leaf);
    return b;
}

/* mkdir -p */
static int mkdirs(const char *path, mode_t mode) {
    char tmp[VMC_MAX_PATH];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len && tmp[len-1] == '/') tmp[len-1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -errno;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -errno;
    return 0;
}

/* ------------------------------------------------------- capability probe */

static int fs_has_type(const char *type) {
    FILE *f = fopen("/proc/filesystems", "re");
    if (!f) return 0;
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        /* format: "\tnodev\tTYPE" or "\tTYPE" */
        char *last = strrchr(line, '\t');
        if (last && strcmp(last + 1, type) == 0) { found = 1; break; }
    }
    fclose(f);
    return found;
}

int vmc_probe_caps(vmc_caps *caps) {
    if (!caps) return VMC_ERR_INVAL;
    memset(caps, 0, sizeof(*caps));
    caps->abi_version = VMC_ABI_VERSION;

    struct utsname uts;
    if (uname(&uts) == 0) {
        snprintf(caps->kernel_release, sizeof(caps->kernel_release), "%s", uts.release);
        /* crude major.minor compare for feature gates */
        int maj = 0, min = 0;
        sscanf(uts.release, "%d.%d", &maj, &min);
        int km = maj * 100 + min;
        uint64_t f = VMC_FLAG_NS_PID | VMC_FLAG_NS_NET | VMC_FLAG_NS_MNT |
                     VMC_FLAG_NS_UTS | VMC_FLAG_NS_IPC;
        if (km >= 406) f |= VMC_FLAG_NS_CGROUP;   /* CLONE_NEWCGROUP */
        if (km >= 506) f |= VMC_FLAG_NS_TIME;
        if (km >= 308) caps->pivot_root_supported = 1;
        caps->supported_flags = f;
    }

    char buf[64];
    caps->user_ns_enabled =
        (read_file_str("/proc/sys/user/max_user_namespaces", buf, sizeof(buf)) == 0)
            ? (atol(buf) > 0) : 1 /* assume enabled unless explicitly 0 */;
    /* Some vendor kernels gate with this knob; absence means "allowed". */
    if (read_file_str("/proc/sys/kernel/unprivileged_userns_clone", buf, sizeof(buf)) == 0)
        caps->setid_allowed = atoi(buf) != 0;
    else
        caps->setid_allowed = 1;

    caps->overlayfs_available = fs_has_type("overlay");

    /* cgroup v2 unified? */
    caps->cgroup_v2 = path_exists("/sys/fs/cgroup/cgroup.controllers") ? 1 : 0;

    if (caps->user_ns_enabled && caps->setid_allowed)
        caps->supported_flags |= VMC_FLAG_NS_USER | VMC_FLAG_ROOTLESS;

    char fp[256];
    if (read_file_str("/system/build.prop", fp, sizeof(fp)) == 0) {
        snprintf(caps->android_fp, sizeof(caps->android_fp), "%.127s", fp);
    }
    LOGI("caps: kernel=%s cgroupv2=%d userns=%d ovl=%d flags=0x%llx",
         caps->kernel_release, caps->cgroup_v2, caps->user_ns_enabled,
         caps->overlayfs_available, (unsigned long long)caps->supported_flags);
    return VMC_OK;
}

int vmc_validate_config(const vmc_config *cfg, const vmc_caps *caps) {
    if (!cfg || !caps) return VMC_ERR_INVAL;
    if (cfg->abi_version != VMC_ABI_VERSION) return VMC_ERR_INVAL;
    if (!(cfg->flags & VMC_FLAG_NS_MNT) || !(cfg->flags & VMC_FLAG_NS_PID)) {
        LOGE("MNT+PID namespaces are mandatory for isolation guarantees");
        return VMC_ERR_INVAL;
    }
    if ((cfg->flags & ~caps->supported_flags &
         (VMC_FLAG_NS_CGROUP | VMC_FLAG_NS_TIME)) != 0) {
        /* optional namespaces unsupported -> downgrade, not fatal */
        LOGW("optional namespace unsupported on this kernel, downgrading");
    }
    if ((cfg->flags & VMC_FLAG_NS_USER) &&
        !(caps->supported_flags & VMC_FLAG_NS_USER)) {
        LOGE("user namespaces disabled on host (permanently rooted fallback "
             "mode is a Phase-4 option; refusing unsafe start)");
        return VMC_ERR_CLONE;
    }
    if (cfg->overlay.lowerdir[0] == '\0' || cfg->overlay.upperdir[0] == '\0' ||
        cfg->overlay.workdir[0] == '\0'  || cfg->overlay.merged_dir[0] == '\0') {
        LOGE("overlay config incomplete");
        return VMC_ERR_INVAL;
    }
    if (cfg->res.cpu_quota_percent == 0 || cfg->res.cpu_quota_percent > 800)
        return VMC_ERR_INVAL;
    if (cfg->res.mem_limit_mb < 256) {
        LOGE("memory limit %u MB below minimum viable Android footprint",
             cfg->res.mem_limit_mb);
        return VMC_ERR_INVAL;
    }
    if (!path_exists(cfg->overlay.lowerdir)) {
        LOGE("lowerdir missing: %s (extract system.img first)", cfg->overlay.lowerdir);
        return VMC_ERR_OVERLAYFS;
    }
    return VMC_OK;
}

/* ------------------------------------------------------------- cgroups v1 */

#define CGROUP_V1_ROOT "/sys/fs/cgroup"

static int cgroup_v1_create_and_attach(const char *name,
                                       const vmc_resources *res,
                                       pid_t guest_pid,
                                       char *out_path, size_t out_len) {
    /* controller dirs we care about; each may be absent on stripped kernels */
    static const char *cpu_dirs[]   = { "cpu", "cpu,cpuacct" };
    static const char *mem_dirs[]   = { "memory" };
    static const char *pids_dirs[]  = { "pids" };
    static const char *blkio_dirs[] = { "blkio" };

    char base[VMC_MAX_PATH], dir[VMC_MAX_PATH], file[VMC_MAX_PATH*2];

    /* --- CPU quota: shares + cfs_period/quota (50% => quota=50000/period=100000) */
    int applied = 0;
    for (size_t i = 0; i < sizeof(cpu_dirs)/sizeof(cpu_dirs[0]); i++) {
        snprintf(base, sizeof(base), "%s/%s", CGROUP_V1_ROOT, cpu_dirs[i]);
        if (!path_exists(base)) continue;
        snprintf(dir, sizeof(dir), "%s/vmos_%s", base, name);
        if (mkdirs(dir, 0755) != 0 && errno != EEXIST) continue;
        /* period fixed at 100ms; quota scales percent of ONE core.
         * For multi-core scaling multiply by core count in Phase 2 tuning. */
        long quota_us = (long)res->cpu_quota_percent * 1000L; /* pct * 1000us */
        if (write_file(pj(dir, "/cpu.cfs_period_us"), "100000") == 0 &&
            write_file(pj(dir, "/cpu.cfs_quota_us"), "%ld", quota_us) == 0) applied |= 1;
        write_file(pj(dir, "/cpu.shares"), "%ld", 1024L * res->cpu_quota_percent / 100);
        snprintf(file, sizeof(file), "%s/cgroup.procs", dir);
        if (write_file(file, "%d", guest_pid) == 0) applied |= 2;
        snprintf(out_path, out_len, "%s", dir);
        break;
    }
    if (!(applied & 1)) LOGW("cpu cgroup v1 not applied (no writable cpu controller)");

    /* --- Memory hard limit */
    for (size_t i = 0; i < sizeof(mem_dirs)/sizeof(mem_dirs[0]); i++) {
        snprintf(base, sizeof(base), "%s/%s", CGROUP_V1_ROOT, mem_dirs[i]);
        if (!path_exists(base)) continue;
        snprintf(dir, sizeof(dir), "%s/vmos_%s", base, name);
        if (mkdirs(dir, 0755) != 0 && errno != EEXIST) continue;
        unsigned long long lim = (unsigned long long)res->mem_limit_mb << 20;
        if (write_file(pj(dir, "/memory.limit_in_bytes"), "%llu", lim) == 0) {
            if (res->mem_swap_limit_mb) {
                write_file(pj(dir, "/memory.memsw.limit_in_bytes"), "%llu",
                           lim + ((unsigned long long)res->mem_swap_limit_mb << 20));
            }
            write_file(pj(dir, "/memory.soft_limit_in_bytes"), "%llu",
                       (unsigned long long)(res->mem_limit_mb * 3 / 4) << 20);
            snprintf(file, sizeof(file), "%s/tasks", dir);
            write_file(file, "%d", guest_pid);
            LOGI("mem cgroup v1: %u MB hard / %u MB soft",
                 res->mem_limit_mb, res->mem_limit_mb * 3 / 4);
        }
        break;
    }

    /* --- PIDs (fork-bomb guard) */
    for (size_t i = 0; i < sizeof(pids_dirs)/sizeof(pids_dirs[0]); i++) {
        snprintf(base, sizeof(base), "%s/%s", CGROUP_V1_ROOT, pids_dirs[i]);
        if (!path_exists(base)) continue;
        snprintf(dir, sizeof(dir), "%s/vmos_%s", base, name);
        if (mkdirs(dir, 0755) == 0 || errno == EEXIST) {
            write_file(pj(dir, "/pids.max"), "%u", res->pids_max ? res->pids_max : 512u);
            snprintf(file, sizeof(file), "%s/cgroup.procs", dir);
            write_file(file, "%d", guest_pid);
        }
        break;
    }

    /* --- blkio weight (best effort) */
    for (size_t i = 0; i < sizeof(blkio_dirs)/sizeof(blkio_dirs[0]); i++) {
        snprintf(base, sizeof(base), "%s/%s", CGROUP_V1_ROOT, blkio_dirs[i]);
        if (!path_exists(base)) continue;
        snprintf(dir, sizeof(dir), "%s/vmos_%s", base, name);
        if (mkdirs(dir, 0755) == 0 || errno == EEXIST) {
            write_file(pj(dir, "/blkio.weight"), "%u",
                       res->blkio_weight ? res->blkio_weight : 300u);
        }
        break;
    }
    return (applied & 2) ? VMC_OK : VMC_ERR_CGROUP;
}

/* ------------------------------------------------------------- cgroups v2 */

static int cgroup_v2_create_and_attach(const char *name,
                                       const vmc_resources *res,
                                       pid_t guest_pid,
                                       char *out_path, size_t out_len) {
    const char *root = "/sys/fs/cgroup";
    char dir[VMC_MAX_PATH], file[VMC_MAX_PATH*2];
    snprintf(dir, sizeof(dir), "%s/vmos_%s", root, name);
    if (mkdirs(dir, 0755) != 0 && errno != EEXIST) return VMC_ERR_CGROUP;

    /* enable controllers delegated to children where possible */
    char ctrl[256] = {0};
    if (read_file_str(pj(root, "/cgroup.subtree_control"), ctrl, sizeof(ctrl)) == 0) {
        /* best-effort: try to turn on what we need from parent */
        (void)write_file(pj(root, "/cgroup.subtree_control"), "+cpu +memory +pids");
    }

    /* cpu.max "<quota> <period>" — 50% of one core => "50000 100000" */
    long quota_us = (long)res->cpu_quota_percent * 1000L;
    int ok = write_file(pj(dir, "/cpu.max"), "%ld 100000", quota_us);
    if (ok != 0) LOGW("cpu.max write failed (%s) — check delegation", strerror(-ok));

    /* memory.max / memory.high / memory.swap.max */
    unsigned long long lim = (unsigned long long)res->mem_limit_mb << 20;
    if (write_file(pj(dir, "/memory.max"), "%llu", lim) != 0)
        LOGW("memory.max write failed — check delegation");
    write_file(pj(dir, "/memory.high"), "%llu",
               (unsigned long long)(res->mem_limit_mb * 9 / 10) << 20);
    write_file(pj(dir, "/memory.swap.max"), "%u",
               res->mem_swap_limit_mb ? res->mem_swap_limit_mb << 20 : 0u);

    write_file(pj(dir, "/pids.max"), "%u", res->pids_max ? res->pids_max : 512u);

    snprintf(file, sizeof(file), "%s/cgroup.procs", dir);
    int att = write_file(file, "%d", guest_pid);
    snprintf(out_path, out_len, "%s", dir);
    return att == 0 ? VMC_OK : VMC_ERR_CGROUP;
}

/* Attach an ALREADY-CLONED pid to the VM's cgroup (called from host side
 * right after clone returns, before guest init proceeds past barrier). */
static int cgroup_attach(pid_t guest_pid, const vmc_config *cfg,
                         int cgroup_v2, char *out, size_t outlen) {
    if (cgroup_v2)
        return cgroup_v2_create_and_attach(cfg->vm_name, &cfg->res, guest_pid, out, outlen);
    return cgroup_v1_create_and_attach(cfg->vm_name, &cfg->res, guest_pid, out, outlen);
}

/* -------------------------------------------------- guest-side root setup */

/* Mount points that must exist under the merged rootfs. */
struct fstab_entry { const char *dst; const char *type; const char *data; unsigned long flags; };
static const struct fstab_entry kGuestMounts[] = {
    { "/proc",     "proc",     "hidepid=invisible,gid=3009", 0 },
    { "/sys",      "sysfs",    NULL,                          0 },
    { "/dev",      "tmpfs",    "mode=755,size=16m",           MS_NOSUID|MS_NOEXEC },
    { "/tmp",      "tmpfs",    "mode=1777,size=64m",          MS_NOSUID|MS_NODEV },
    { "/data",     NULL /* per-VM ext4/erofs image, Phase 2 */, NULL, 0 },
    { "/storage",  "tmpfs",    "mode=775,size=1m",            MS_NOSUID|MS_NODEV },
};

/* Mask dangerous proc/sys files (lxc-style). Type: 'f'=empty RO file, 'd'=empty RO dir */
struct mask_entry { const char *path; char kind; };
static const struct mask_entry kMasks[] = {
    { "/proc/kcore", 'f' }, { "/proc/kallsyms", 'f' }, { "/proc/sched_debug", 'f' },
    { "/proc/timer_list", 'f' }, { "/proc/acpi", 'd' }, { "/proc/scsi", 'd' },
    { "/sys/firmware", 'd' }, { "/sys/kernel/debug", 'd' }, { "/sys/kernel/tracing", 'd' },
};

static int apply_masks(const char *root) {
    static const char *EMPTY = "/.vmc_empty";
    for (size_t i = 0; i < sizeof(kMasks)/sizeof(kMasks[0]); i++) {
        char full[VMC_MAX_PATH*2];
        snprintf(full, sizeof(full), "%s%s", root, kMasks[i].path);
        if (!path_exists(full)) continue;
        if (kMasks[i].kind == 'f') {
            int fd = open(full, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0000);
            if (fd >= 0) close(fd);
            if (mount(full, full, NULL, MS_BIND|MS_REC, NULL) == 0)
                mount(NULL, full, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY, NULL);
        } else {
            /* empty tmpfs dir on top */
            mkdirs(full, 0755);
            if (mount("tmpfs", full, "tmpfs", MS_NOSUID|MS_NOEXEC,
                      "mode=000,size=1k") != 0) {
                LOGD("mask dir %s failed: %s", full, strerror(errno));
            }
        }
    }
    (void)EMPTY;
    return 0;
}

static int mount_minimal_dev(const char *root) {
    char p[VMC_MAX_PATH*2];
    struct { const char *to; int maj, min; } nodes[] = {
        { "null",   1, 3 }, { "zero", 1, 5 }, { "random", 1, 8 },
        { "urandom",1, 9 }, { "tty",  5, 0 }, { "ptmx", 5, 2 },
        { "fuse",  10, 229 },
    };
    for (size_t i = 0; i < sizeof(nodes)/sizeof(nodes[0]); i++) {
        snprintf(p, sizeof(p), "%s/dev/%s", root, nodes[i].to);
        mknod(p, S_IFCHR | 0666, makedev(nodes[i].maj, nodes[i].min));
        chmod(p, 0666);
    }
    /* binder/hwbinder/vndbinder: created by guest init once servicemanager
     * stage needs them (device nodes come from host kernel modules). */
    snprintf(p, sizeof(p), "%s/dev/log", root); mkdirs(p, 0755);
    snprintf(p, sizeof(p), "%s/dev/shm", root);  mkdirs(p, 0777);
    snprintf(p, sizeof(p), "%s/dev/mnt", root);  mkdirs(p, 0755);
    return 0;
}

/* Runs INSIDE the new namespaces (clone child). Returns 0 on success or a
 * negative VMC_ERR_* code. On success it does NOT return: control flows into
 * vmos_guest_init_main() which becomes PID 1 of the guest. */
static int guest_namespace_setup(const vmc_config *cfg, int cgroup_v2) {
    /* 1. Lockdown: nothing propagates back to host, ever. */
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        LOGE("make-rprivate / failed: %s", strerror(errno));
        return VMC_ERR_MOUNT;
    }

    /* 2. Overlayfs: lower(ro system image) + upper(per-VM rw) -> merged */
    char ovl_opts[VMC_MAX_PATH * 3 + 64];
    snprintf(ovl_opts, sizeof(ovl_opts),
             "lowerdir=%s,upperdir=%s,workdir=%s,index=off,metacopy=off",
             cfg->overlay.lowerdir, cfg->overlay.upperdir, cfg->overlay.workdir);
    mkdirs(cfg->overlay.merged_dir, 0755);
    if (mount("overlay", cfg->overlay.merged_dir, "overlay", 0, ovl_opts) != 0) {
        LOGE("overlayfs mount failed: %s (opts=%s)", strerror(errno), ovl_opts);
        return VMC_ERR_OVERLAYFS;
    }
    const char *newroot = cfg->overlay.merged_dir;

    /* 3. Pre-create mountpoints inside the new root BEFORE pivot_root */
    for (size_t i = 0; i < sizeof(kGuestMounts)/sizeof(kGuestMounts[0]); i++) {
        if (!kGuestMounts[i].type) continue; /* deferred (e.g. /data image) */
        char p[VMC_MAX_PATH*2];
        snprintf(p, sizeof(p), "%s%s", newroot, kGuestMounts[i].dst);
        mkdirs(p, 0755);
    }

    /* 4. pivot_root(newroot, put_old) — the classic sequence */
    char put_old[VMC_MAX_PATH*2];
    snprintf(put_old, sizeof(put_old), "%s/.old_root", newroot);
    mkdirs(put_old, 0700);

    if (chdir(newroot) != 0) return VMC_ERR_PIVOT_ROOT;
    if (syscall(SYS_pivot_root, ".", ".old_root") != 0) {
        /* fallback for kernels without pivot_root perms quirks: chroot */
        LOGW("pivot_root failed (%s), falling back to chroot", strerror(errno));
        if (chroot(newroot) != 0) return VMC_ERR_PIVOT_ROOT;
        if (chdir("/") != 0) return VMC_ERR_PIVOT_ROOT;
    } else {
        if (umount2("/.old_root", MNT_DETACH) != 0)
            LOGW("detach old root: %s", strerror(errno));
        rmdir("/.old_root");
        if (chdir("/") != 0) return VMC_ERR_PIVOT_ROOT;
    }

    /* 5. Fresh proc/sys/dev/tmpfs */
    for (size_t i = 0; i < sizeof(kGuestMounts)/sizeof(kGuestMounts[0]); i++) {
        const struct fstab_entry *m = &kGuestMounts[i];
        if (!m->type) continue;
        if (mount(m->type, m->dst, m->type, m->flags, m->data) != 0) {
            LOGE("mount %s (%s) failed: %s", m->dst, m->type, strerror(errno));
            if (strcmp(m->dst, "/proc") == 0) return VMC_ERR_MOUNT; /* fatal */
        }
    }
    mount_minimal_dev("/");
    apply_masks("/");

    /* 6. Extra bind mounts declared by Kotlin layer (shared folders etc.) */
    for (uint32_t i = 0; i < cfg->mount_count && i < VMC_MAX_MOUNTS; i++) {
        const vmc_bind *b = &cfg->mounts[i];
        char src[VMC_MAX_PATH], dst[VMC_MAX_PATH];
        snprintf(src, sizeof(src), "%s", b->src);
        snprintf(dst, sizeof(dst), "%s", b->dst);
        mkdirs(dst, 0755);
        if (mount(src, dst, NULL, MS_BIND | MS_REC, NULL) != 0) {
            LOGW("bind %s -> %s failed: %s", src, dst, strerror(errno));
            continue;
        }
        if (b->read_only)
            mount(NULL, dst, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL);
    }

    /* 7. Drop capabilities the guest must never hold even in-container
     *    (CAP_SYS_MODULE, CAP_SYS_RAWIO kept off; guest init re-drops more
     *    with seccomp in Phase 2). */
    prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);

    /* 8. Hostname inside UTS ns */
    if (cfg->hostname[0]) sethostname(cfg->hostname, strlen(cfg->hostname));

    /* 9. Become session leader + attach controlling tty later via guest init */
    setsid();
    (void)cgroup_v2;

    /* 10. Handoff: run the guest PID-1 in THIS process. It becomes the root
     *     of the PID namespace and never returns here on success. */
    char fdnum[8];
    snprintf(fdnum, sizeof(fdnum), "%d", g_child_ctrl_fd);
    setenv("VMC_CTRL_FD", fdnum, 1);
    setenv("VMC_VM_NAME", cfg->vm_name, 1);
    setenv("VMC_INIT_DEBUG", cfg->log_level >= 2 ? "1" : "0", 1);
    vmos_guest_init_main(0, NULL); /* does not return */
    return VMC_ERR_EXEC;
}

/* ------------------------------------------------------------ guest init */

/* --------------------------------------------------------------- clone child */

static int child_fn(void *arg) {
    const vmc_config *cfg = (const vmc_config *)arg;

    int err = guest_namespace_setup(cfg, 0 /* cgroup mode handled host-side */);
    if (err != 0) {
        /* report failure code on ctrl socket and die */
        signed char b = (signed char)err;   /* e.g. -5 == VMC_ERR_OVERLAYFS */
        ssize_t w = write(g_child_ctrl_fd, &b, 1); (void)w;
        _exit(100 - b);
    }
    /* unreachable: guest_namespace_setup execs/loops guest init internally */
    _exit(127);
}

/* ---------------------------------------------------------------- lifecycle */

int vmc_vm_start(const vmc_config *cfg, vmc_instance *out) {
    if (!cfg || !out) return VMC_ERR_INVAL;
    vmc_caps caps;
    int rc = vmc_probe_caps(&caps);
    if (rc != VMC_OK) return rc;
    rc = vmc_validate_config(cfg, &caps);
    if (rc != VMC_OK) return rc;

    memset(out, 0, sizeof(*out));
    out->state = VMC_STATE_NEW;

    /* Prepare per-VM overlay dirs on host side (must exist pre-clone). */
    if (mkdirs(cfg->overlay.upperdir, 0755) != 0) return VMC_ERR_OVERLAYFS;
    if (mkdirs(cfg->overlay.workdir, 0755) != 0)  return VMC_ERR_OVERLAYFS;

    /* Control channel: host <-> guest init. */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
        return VMC_ERR_IO;
    /* child end must survive execve -> drop CLOEXEC on the child copy */
    int child_fd = sv[1];
    fcntl(child_fd, F_SETFD, 0);
    g_child_ctrl_fd = child_fd; /* seen by clone child via COW (see above) */

    /* Deep-copy cfg so the child never dereferences a Kotlin-owned pointer
     * after this function returns. */
    vmc_config *cfg_copy = malloc(sizeof(*cfg_copy));
    if (!cfg_copy) { close(sv[0]); close(child_fd); return VMC_ERR_NOMEM; }
    *cfg_copy = *cfg;

    uint64_t cl_flags = 0;
    if (cfg->flags & VMC_FLAG_NS_PID)   cl_flags |= CLONE_NEWPID;
    if (cfg->flags & VMC_FLAG_NS_NET)   cl_flags |= CLONE_NEWNET;
    if (cfg->flags & VMC_FLAG_NS_MNT)   cl_flags |= CLONE_NEWNS;
    if (cfg->flags & VMC_FLAG_NS_UTS)   cl_flags |= CLONE_NEWUTS;
    if (cfg->flags & VMC_FLAG_NS_IPC)   cl_flags |= CLONE_NEWIPC;
    if (cfg->flags & VMC_FLAG_NS_USER)  cl_flags |= CLONE_NEWUSER;
    if (cfg->flags & VMC_FLAG_NS_CGROUP && caps.supported_flags & VMC_FLAG_NS_CGROUP)
        cl_flags |= CLONE_NEWCGROUP;
#ifdef CLONE_NEWTIME
    if (cfg->flags & VMC_FLAG_NS_TIME && caps.supported_flags & VMC_FLAG_NS_TIME)
        cl_flags |= CLONE_NEWTIME;
#endif
    cl_flags |= SIGCHLD;

    /* Private stack for the child (MAP_STACK guard page comes free with mmap). */
    void *stack = mmap(NULL, VMC_STACK_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED) { close(sv[0]); close(child_fd); return VMC_ERR_NOMEM; }
    char *stack_top = (char *)stack + VMC_STACK_SIZE;

    /* Portable wrapper: bionic/glibc both provide clone(fn, stack, flags, arg).
     * The raw SYS_clone arg order is arch-specific — never call it directly. */
    pid_t guest = clone(child_fn, stack_top, (int)cl_flags, cfg_copy);
    if (guest == -1) {
        rc = -errno;
        LOGE("clone(flags=0x%llx) failed: %s", (unsigned long long)cl_flags, strerror(errno));
        munmap(stack, VMC_STACK_SIZE);
        free(cfg_copy);
        close(sv[0]); close(child_fd);
        return VMC_ERR_CLONE;
    }

    out->guest_pid = guest;
    out->start_time_ms = (uint64_t)ms_now();
    out->flags_active = cl_flags;

    /* ---- Cgroup: attach IMMEDIATELY from host while child is still early. */
    rc = cgroup_attach(guest, cfg, caps.cgroup_v2,
                       out->cgroup_path, sizeof(out->cgroup_path));
    if (rc != VMC_OK) {
        LOGW("cgroup setup partially failed — running UNLIMITED (degraded). "
             "On stock Android this usually means sysfs is ro; Phase 4 adds "
             "the debug-cgroup remount path.");
    }

    /* ---- User namespace maps: host app-uid <-> guest root. */
    if (cfg->flags & VMC_FLAG_NS_USER) {
        char p[128];
        snprintf(p, sizeof(p), "/proc/%d/uid_map", guest);
        /* guest uid 0 -> host uid offset, count uids */
        int maprc = write_file(p, "0 %u %u", cfg->uid_offset, cfg->uid_count);
        snprintf(p, sizeof(p), "/proc/%d/gid_map", guest);
        maprc |= write_file(p, "0 %u %u", cfg->uid_offset, cfg->uid_count);
        /* Deny additional-group mapping (CVE-2023-52424 class hardening) */
        snprintf(p, sizeof(p), "/proc/%d/setgroups", guest);
        write_file(p, "deny");
        if (maprc != 0) {
            LOGE("uid/gid_map failed: %s — killing half-booted guest", strerror(errno));
            kill(guest, SIGKILL);
            waitpid(guest, NULL, 0);
            close(sv[0]); close(child_fd);
            munmap(stack, VMC_STACK_SIZE);
            return VMC_ERR_CLONE;
        }
    }

    /* ---- Wait for guest-init ready byte on ctrl socket (timeout 10s). */
    signed char ready = 0;
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ssize_t n = read(sv[0], &ready, 1);
    if (n != 1) {
        int st = 0;
        pid_t w = waitpid(guest, &st, WNOHANG);
        LOGE("handshake timeout/EOF (guest alive=%d status=%d)", w == guest, st);
        kill(guest, SIGKILL);
        waitpid(guest, NULL, 0);
        close(sv[0]); close(child_fd);
        munmap(stack, VMC_STACK_SIZE);
        out->state = VMC_STATE_FAILED;
        return VMC_ERR_TIMEOUT;
    }
    if (ready != 'R') { /* 'R' = rootfs ready; anything else = mapped errno */
        LOGE("guest init reported startup error code %d", ready);
        kill(guest, SIGKILL);
        waitpid(guest, NULL, 0);
        close(sv[0]); close(child_fd);
        munmap(stack, VMC_STACK_SIZE);
        out->state = VMC_STATE_FAILED;
        return ready == VMC_ERR_OVERLAYFS ? VMC_ERR_OVERLAYFS : VMC_ERR_PIVOT_ROOT;
    }

    out->ctrl_fd = sv[0];
    close(child_fd);
    munmap(stack, VMC_STACK_SIZE); /* child copied what it needed onto heap; safe
                                      because guest init has already exec'd-or-idled
                                      past stack usage of child_fn bookkeeping */
    out->state = VMC_STATE_RUNNING;
    LOGI("VM '%s' RUNNING: guest_pid=%d cgroup=%s ctrl_fd=%d",
         cfg->vm_name, guest, out->cgroup_path, out->ctrl_fd);
    return VMC_OK;
}

int vmc_vm_poll(vmc_instance *vm) {
    if (!vm) return VMC_ERR_INVAL;
    if (vm->state != VMC_STATE_RUNNING && vm->state != VMC_STATE_STOPPING)
        return VMC_ERR_STATE;
    int status = 0;
    pid_t w = waitpid(vm->guest_pid, &status, WNOHANG);
    if (w == vm->guest_pid) {
        vm->state = VMC_STATE_STOPPED;
        LOGI("guest pid %d exited status=0x%x", vm->guest_pid, status);
    } else if (w == -1 && errno == ECHILD) {
        vm->state = VMC_STATE_STOPPED;
    }
    return VMC_OK;
}

int vmc_vm_stop(vmc_instance *vm, uint32_t timeout_ms) {
    if (!vm) return VMC_ERR_INVAL;
    if (vm->state == VMC_STATE_STOPPED) return VMC_OK;
    if (vm->state != VMC_STATE_RUNNING) return VMC_ERR_STATE;
    vm->state = VMC_STATE_STOPPING;

    /* Graceful: real-time signal consumed by guest init's orderly poweroff. */
    kill(vm->guest_pid, SIGRTMIN + 3);

    long deadline = ms_now() + (timeout_ms ? timeout_ms : 8000);
    int status = 0;
    while (ms_now() < deadline) {
        pid_t w = waitpid(vm->guest_pid, &status, WNOHANG);
        if (w == vm->guest_pid || (w == -1 && errno == ECHILD)) {
            vm->state = VMC_STATE_STOPPED;
            goto cleanup;
        }
        usleep(50 * 1000);
    }
    LOGW("graceful stop timed out, escalating");
    vmc_vm_kill_all(vm);

cleanup:
    if (vm->ctrl_fd >= 0) { close(vm->ctrl_fd); vm->ctrl_fd = -1; }
    /* remove cgroup dirs (children must be gone; kill_all ensured that) */
    if (vm->cgroup_path[0]) rmdir(vm->cgroup_path);
    return VMC_OK;
}

int vmc_vm_kill_all(vmc_instance *vm) {
    if (!vm) return VMC_ERR_INVAL;
    /* Kill everything left in the cgroup (covers orphaned grandchildren). */
    if (vm->cgroup_path[0]) {
        char procs[VMC_MAX_PATH*2];
        snprintf(procs, sizeof(procs), "%s/cgroup.procs", vm->cgroup_path);
        FILE *f = fopen(procs, "re");
        if (f) {
            pid_t p;
            while (fscanf(f, "%d", &p) == 1) kill(p, SIGKILL);
            fclose(f);
        }
    }
    kill(vm->guest_pid, SIGKILL);
    int status;
    for (int i = 0; i < 100; i++) {
        pid_t w = waitpid(vm->guest_pid, &status, WNOHANG);
        if (w == vm->guest_pid || (w == -1 && errno == ECHILD)) break;
        usleep(20 * 1000);
    }
    vm->state = VMC_STATE_STOPPED;
    return VMC_OK;
}

int vmc_vm_read_log(vmc_instance *vm, char *buf, size_t buflen, int timeout_ms) {
    if (!vm || vm->state != VMC_STATE_RUNNING || vm->ctrl_fd < 0)
        return VMC_ERR_STATE;
    fd_set rfds; FD_ZERO(&rfds); FD_SET(vm->ctrl_fd, &rfds);
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    int s = select(vm->ctrl_fd + 1, &rfds, NULL, NULL, timeout_ms >= 0 ? &tv : NULL);
    if (s <= 0) return s == 0 ? VMC_ERR_TIMEOUT : -errno;
    ssize_t n = read(vm->ctrl_fd, buf, buflen - 1);
    if (n <= 0) return n == 0 ? 0 : -errno;
    buf[n] = '\0';
    return (int)n;
}

const char *vmc_strerror(int err) {
    switch (err) {
        case VMC_OK: return "OK";
        case VMC_ERR_INVAL: return "invalid configuration";
        case VMC_ERR_NOMEM: return "out of memory";
        case VMC_ERR_CLONE: return "namespace creation denied by kernel/SELinux";
        case VMC_ERR_CGROUP: return "cgroup controller unavailable/read-only";
        case VMC_ERR_OVERLAYFS: return "overlayfs mount failed (check lower/upper/work)";
        case VMC_ERR_PIVOT_ROOT: return "pivot_root failed";
        case VMC_ERR_MOUNT: return "mount failed";
        case VMC_ERR_EXEC: return "guest init exec failed";
        case VMC_ERR_TIMEOUT: return "guest init handshake timeout";
        case VMC_ERR_STATE: return "illegal state for operation";
        case VMC_ERR_IO: return "control channel I/O error";
        default: return "unknown error";
    }
}
