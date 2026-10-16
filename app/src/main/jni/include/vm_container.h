/*
 * vm_container.h — Public C ABI of libvmcontainer (VMOS Clone, Phase 1)
 *
 * This header is the single contract between:
 *   - the Kotlin/JNI layer (app/src/main/java/com/aswe/vmos/jni)
 *   - the native container runtime (app/src/main/jni/container)
 *   - the guest init that runs as PID 1 inside the new namespaces
 *     (app/src/main/jni/guest_init.c, linked into vmos-guest-init)
 *
 * Everything here is position-independent and free of libc++ ABI leakage:
 * plain structs + extern "C" functions so it can be consumed from C, C++,
 * and via JNI without name-mangling headaches.
 */
#ifndef VM_CONTAINER_H_
#define VM_CONTAINER_H_

#include <sys/types.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VMC_ABI_VERSION   1u
#define VMC_MAX_PATH      512
#define VMC_MAX_NAME      64
#define VMC_MAX_MOUNTS    32
#define VMC_STACK_SIZE    (8u * 1024u * 1024u)   /* clone() child stack: 8 MiB */

/* Error codes (negative = failure). Stable across releases; never renumber. */
enum vmc_error {
    VMC_OK                 =  0,
    VMC_ERR_INVAL          = -1,   /* bad argument / ABI mismatch        */
    VMC_ERR_NOMEM          = -2,   /* malloc / stack mmap failed         */
    VMC_ERR_CLONE          = -3,   /* clone()/unshare() rejected         */
    VMC_ERR_CGROUP         = -4,   /* cgroup create/attach failed        */
    VMC_ERR_OVERLAYFS      = -5,   /* overlayfs mount failed             */
    VMC_ERR_PIVOT_ROOT     = -6,   /* pivot_root sequence failed         */
    VMC_ERR_MOUNT          = -7,   /* generic bind/tmpfs mount failed    */
    VMC_ERR_EXEC           = -8,   /* execve of guest init failed        */
    VMC_ERR_TIMEOUT        = -9,   /* handshake with guest init timeout  */
    VMC_ERR_STATE          = -10,  /* API used in wrong lifecycle state  */
    VMC_ERR_IO             = -11,  /* read/write on control pipe failed  */
};

/* Isolation feature flags — bit set == request that isolation.
 * The runtime checks kernel support at startup (see caps probe) and will
 * refuse to start a VM if a REQUIRED flag is unsupported. */
#define VMC_FLAG_NS_PID      (1u << 0)
#define VMC_FLAG_NS_NET      (1u << 1)
#define VMC_FLAG_NS_MNT      (1u << 2)
#define VMC_FLAG_NS_UTS      (1u << 3)
#define VMC_FLAG_NS_IPC      (1u << 4)
#define VMC_FLAG_NS_USER     (1u << 5)   /* unprivileged root-within-container */
#define VMC_FLAG_NS_CGROUP   (1u << 6)   /* Android 11+/kernel 4.6+            */
#define VMC_FLAG_NS_TIME     (1u << 7)   /* kernel 5.6+, optional              */
#define VMC_FLAG_ROOTLESS    (1u << 8)   /* no host privileges needed          */
#define VMC_FLAG_SELINUX_ATRAN       (1u << 9)
#define VMC_FLAG_SELINUX_NORELABEL   (1u << 10)

/* Default full-isolation set requested by the Kotlin layer. */
#define VMC_FLAGS_DEFAULT \
    (VMC_FLAG_NS_PID | VMC_FLAG_NS_NET | VMC_FLAG_NS_MNT | VMC_FLAG_NS_UTS | \
     VMC_FLAG_NS_IPC | VMC_FLAG_NS_USER | VMC_FLAG_NS_CGROUP)

/* Overlayfs description of the guest rootfs (Phase 1 item 3). */
typedef struct vmc_overlay_cfg {
    char lowerdir[VMC_MAX_PATH];   /* read-only system image (squashfs mount point) */
    char upperdir[VMC_MAX_PATH];   /* per-VM writable diff dir                      */
    char workdir[VMC_MAX_PATH];    /* per-VM overlay work dir (same fs as upper)    */
    char merged_dir[VMC_MAX_PATH]; /* where overlay gets mounted (inside new mount ns) */
} vmc_overlay_cfg;

/* Bind mounts injected into the guest after pivot_root. src may contain
 * ${ROOT}, expanded to the guest rootfs path. */
typedef struct vmc_bind {
    char src[VMC_MAX_PATH];
    char dst[VMC_MAX_PATH];        /* relative to new root unless leading '/'  */
    int  read_only;
} vmc_bind;

/* Resource limits applied through cgroups v1 or v2 (Phase 1 item 2). */
typedef struct vmc_resources {
    uint32_t cpu_quota_percent;    /* 1..100*ncores; 50 => half a core          */
    uint32_t mem_limit_mb;         /* hard limit, e.g. 2048 for 2 GiB           */
    uint32_t mem_swap_limit_mb;    /* 0 disables swap accounting                */
    uint32_t pids_max;             /* fork-bomb guard                           */
    uint32_t blkio_weight;         /* 10..1000, cgroup v1 blkio.weight          */
} vmc_resources;

/* Full boot configuration handed over JNI (mirrors Kotlin VMConfig). */
typedef struct vmc_config {
    uint32_t    abi_version;       /* must be VMC_ABI_VERSION                   */
    char        vm_name[VMC_MAX_NAME];
    uint64_t    flags;             /* VMC_FLAG_* mask                           */
    vmc_overlay_cfg overlay;
    char        init_path[VMC_MAX_PATH];   /* guest init inside rootfs, e.g. /init */
    uint32_t    uid_offset;        /* host uid mapped to guest root, e.g. appuid+1 */
    uint32_t    uid_count;         /* sub-uids reserved for the guest            */
    vmc_resources res;
    uint32_t    mount_count;
    vmc_bind    mounts[VMC_MAX_MOUNTS];
    char        hostname[VMC_MAX_NAME];
    uint32_t    log_level;         /* 0=quiet 1=info 2=verbose                  */
} vmc_config;

/* Runtime state machine. */
typedef enum vmc_state {
    VMC_STATE_NEW = 0,
    VMC_STATE_RUNNING,
    VMC_STATE_STOPPING,
    VMC_STATE_STOPPED,
    VMC_STATE_FAILED,
} vmc_state;

/* Live instance handle (opaque contents stable for diagnostics). */
typedef struct vmc_instance {
    pid_t    guest_pid;            /* PID 1 of the guest (host namespace)      */
    vmc_state state;
    int      ctrl_fd;              /* socketpair to guest init                 */
    char     cgroup_path[VMC_MAX_PATH];
    uint64_t flags_active;         /* flags actually granted by kernel         */
    uint64_t start_time_ms;
} vmc_instance;

/* Kernel capability report (populated by vmc_probe_caps). */
typedef struct vmc_caps {
    uint32_t abi_version;
    uint64_t supported_flags;      /* subset of VMC_FLAG_* usable right now    */
    int      cgroup_v2;            /* 1 unified hierarchy, 0 legacy v1         */
    int      user_ns_enabled;      /* /proc/sys/user/max_user_namespaces > 0   */
    int      setid_allowed;        /* /proc/sys/kernel/unprivileged_userns_clone != 0 */
    int      overlayfs_available;  /* present in /proc/filesystems             */
    int      pivot_root_supported; /* >= 3.8                                   */
    char     kernel_release[64];
    char     android_fp[128];
} vmc_caps;

/* ---- Lifecycle API ---------------------------------------------------- */

/* Probe kernel capabilities once at app start. Fills *caps (zeroed first). */
int  vmc_probe_caps(vmc_caps *caps);

/* Validate cfg against caps WITHOUT touching namespaces. Returns VMC_OK or err. */
int  vmc_validate_config(const vmc_config *cfg, const vmc_caps *caps);

/* Boot the container: clone() -> namespaces -> cgroup -> overlayfs ->
 * pivot_root -> handshake -> exec guest init. Blocks until the guest init
 * confirms rootfs takeover (or timeout). On success *out holds the handle. */
int  vmc_vm_start(const vmc_config *cfg, vmc_instance *out);

/* SIGRTMIN+3 -> guest init performs orderly shutdown. Waits up to
 * timeout_ms for exit. Idempotent. */
int  vmc_vm_stop(vmc_instance *vm, uint32_t timeout_ms);

/* Force kill everything in the guest (guest init double-fork watchdog uses
 * this on ctrl socket EOF). */
int  vmc_vm_kill_all(vmc_instance *vm);

/* Non-blocking status poll; updates vm->state. */
int  vmc_vm_poll(vmc_instance *vm);

/* Read one line of guest console output (pty bridge). Returns bytes copied,
 * 0 on EOF, negative error. Used by the Kotlin log pump thread. */
int  vmc_vm_read_log(vmc_instance *vm, char *buf, size_t buflen, int timeout_ms);

const char *vmc_strerror(int err);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* VM_CONTAINER_H_ */
