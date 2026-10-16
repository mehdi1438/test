/*
 * guest_init.c — PID 1 inside the guest namespaces (Phase 1 minimal version).
 *
 * Today this is a "container shell" init: it confirms rootfs takeover to the
 * host over the inherited control socket, then reaps children forever.
 * In Phase 3 it grows into the trimmed AOSP `init` (property service,
 * ueventd-lite, service restart supervision, seccomp application, and the
 * Binder namespace proxy bootstrap).
 *
 * Contract with vm_container.c:
 *   - runs as the clone() child, already chrooted/pivot_rooted into the
 *     overlay merged root, in fresh PID/NET/MNT/UTS/IPC(/USER/CGROUP) ns.
 *   - VMC_CTRL_FD env var = fd of the connected socketpair end.
 *   - writes 'R' when the guest root is confirmed live.
 *   - responds to SIGRTMIN+3 with an orderly shutdown (host vmc_vm_stop).
 *   - on ctrl-socket EOF (host app died), kills every process left in the
 *     PID namespace so no orphan keeps burning phone battery.
 */
#define _GNU_SOURCE
#include "vm_container.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef MNT_DETACH
#define MNT_DETACH 2
#endif

#define LOG_TAG "guest-init"
#include "vm_log.h"

static volatile sig_atomic_t g_shutdown = 0;
static int g_ctrl_fd = -1;

static void on_shutdown(int sig) { (void)sig; g_shutdown = 1; }

static void kill_everyone(void) {
    /* Sweep the whole PID namespace. As PID 1 we see all guests. */
    DIR *d = opendir("/proc");
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            pid_t p = atoi(e->d_name);
            if (p > 1) kill(p, SIGKILL);
        }
        closedir(d);
    }
}

int vmos_guest_init_main(int argc, char **argv) {
    (void)argc; (void)argv;

    const char *fdenv = getenv("VMC_CTRL_FD");
    g_ctrl_fd = fdenv ? atoi(fdenv) : -1;

    /* Signal dispositions: PID 1 must never die from stray signals. */
    struct sigaction sa = { .sa_handler = on_shutdown };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGRTMIN + 3, &sa, NULL);          /* orderly poweroff request */
    signal(SIGCHLD, SIG_DFL);                     /* we reap explicitly      */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, on_shutdown);                 /* early-boot convenience  */

    /* Mount the last pieces of a bootable Android-ish root that require
     * being INSIDE the mount ns after pivot_root (kept here rather than in
     * the host lib so the split stays clean). */
    mkdir("/dev/pts", 0755);
    if (mount("devpts", "/dev/pts", "devpts",
              MS_NOSUID | MS_NOEXEC, "ptmxmode=0666,gid=5") != 0)
        LOGW("devpts: %s", strerror(errno));

    /* Property tmpfs for Phase 3's property_service. */
    mkdir("/dev/__properties__", 0755);
    if (mount("tmpfs", "/dev/__properties__", "tmpfs",
              MS_NOSUID | MS_NOEXEC, "size=1m,mode=755") != 0)
        LOGW("props tmpfs: %s", strerror(errno));

    /* Confirm liveness to the host. */
    if (g_ctrl_fd >= 0) {
        char r = 'R';
        if (write(g_ctrl_fd, &r, 1) != 1)
            LOGW("ready byte write failed: %s", strerror(errno));
    }
    LOGI("guest init up: name=%s pid=%d", getenv("VMC_VM_NAME") ?: "?", getpid());

    /* ---- Supervision loop (becomes service manager in Phase 3) ---- */
    while (!g_shutdown) {
        int status = 0;
        pid_t w = waitpid(-1, &status, WNOHANG);
        if (w > 0) {
            LOGD("reaped %d status=0x%x", w, status);
            continue;
        }

        /* Poll ctrl socket: EOF => host app gone => shut down cleanly. */
        if (g_ctrl_fd >= 0) {
            fd_set rfds; FD_ZERO(&rfds); FD_SET(g_ctrl_fd, &rfds);
            struct timeval tv = { .tv_sec = 0, .tv_usec = 200 * 1000 };
            int s = select(g_ctrl_fd + 1, &rfds, NULL, NULL, &tv);
            if (s > 0 && FD_ISSET(g_ctrl_fd, &rfds)) {
                char b;
                ssize_t n = read(g_ctrl_fd, &b, 1);
                if (n == 0) {
                    LOGI("host channel closed — powering off guest");
                    g_shutdown = 1;
                } else if (n < 0 && errno != EAGAIN && errno != EINTR) {
                    g_shutdown = 1;
                }
                /* command bytes reserved: 'L'=loglevel, 'S'=snapshot (P2+) */
            }
        } else {
            usleep(200 * 1000);
        }
    }

    LOGI("orderly shutdown beginning");
    kill_everyone();
    /* Reap stragglers briefly */
    for (int i = 0; i < 20; i++) {
        if (waitpid(-1, NULL, WNOHANG) <= 0) break;
        usleep(50 * 1000);
    }
    /* Detach filesystems best-effort (kernel cleans ns mounts anyway). */
    umount2("/dev/pts", MNT_DETACH);
    umount2("/dev/__properties__", MNT_DETACH);
    LOGI("guest init exiting");
    _exit(0);
}
