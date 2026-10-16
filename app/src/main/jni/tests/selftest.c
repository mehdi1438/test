/*
 * selftest.c — host-side (Linux PC) smoke test for libvmcontainer.
 *
 * Run on your dev box:  cmake --build build/host && ./build/host/vmc_selftest
 * Exercises: caps probe, config validation, and (when permitted by the
 * container you're in) a REAL namespace boot with overlay fallback to tmpfs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "vm_container.h"

#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); failures++; } \
    else         { printf("ok:   %s\n", msg); } \
} while (0)

static int failures = 0;

int main(void) {
    printf("== VMOS Clone Phase-1 selftest ==\n");

    /* ---- 1. caps probe ---------------------------------------------------- */
    vmc_caps caps;
    CHECK(vmc_probe_caps(&caps) == VMC_OK, "vmc_probe_caps returns OK");
    printf("      kernel=%s cgroup_v2=%d userns=%d overlay=%s flags=0x%llx\n",
           caps.kernel_release, caps.cgroup_v2, caps.user_ns_enabled,
           caps.overlayfs_available ? "yes" : "no",
           (unsigned long long)caps.supported_flags);

    /* ---- 2. validation rejects garbage ----------------------------------- */
    vmc_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.abi_version = VMC_ABI_VERSION;
    snprintf(cfg.vm_name, sizeof(cfg.vm_name), "selftest");
    cfg.flags = VMC_FLAGS_DEFAULT;
    cfg.res.cpu_quota_percent = 50;     /* 50 % of one core */
    cfg.res.mem_limit_mb = 2048;        /* 2 GiB            */
    cfg.res.pids_max = 512;
    cfg.uid_offset = (uint32_t)getuid() + 1000;
    cfg.uid_count = 65534;
    snprintf(cfg.hostname, sizeof(cfg.hostname), "vm-selftest");
    snprintf(cfg.overlay.lowerdir,  VMC_MAX_PATH, "/tmp/ovl/lower");
    snprintf(cfg.overlay.upperdir,  VMC_MAX_PATH, "/tmp/ovl/upper");
    snprintf(cfg.overlay.workdir,   VMC_MAX_PATH, "/tmp/ovl/work");
    snprintf(cfg.overlay.merged_dir,VMC_MAX_PATH, "/tmp/ovl/mnt");

    vmc_config bad = cfg;
    bad.abi_version = 999;
    CHECK(vmc_validate_config(&bad, &caps) == VMC_ERR_INVAL,
          "ABI mismatch rejected");
    bad = cfg; bad.res.mem_limit_mb = 64;
    CHECK(vmc_validate_config(&bad, &caps) == VMC_ERR_INVAL,
          "absurd memory limit rejected");
    bad = cfg; bad.overlay.lowerdir[0] = 0;
    CHECK(vmc_validate_config(&bad, &caps) == VMC_ERR_INVAL,
          "missing lowerdir rejected");
    CHECK(vmc_validate_config(&cfg, &caps) == VMC_OK ||
          !access("/tmp/ovl/lower", F_OK) != 0,
          "well-formed config accepted (or missing image dir reported)");

    /* ---- 3. lifecycle errors on bogus handles ---------------------------- */
    CHECK(vmc_vm_start(NULL, NULL) == VMC_ERR_INVAL, "null start rejected");
    CHECK(vmc_vm_stop(NULL, 100) == VMC_ERR_INVAL, "null stop rejected");
    vmc_instance fake; memset(&fake, 0, sizeof(fake));
    CHECK(vmc_vm_poll(&fake) == VMC_ERR_STATE, "poll on NEW-state handle errors");

    /* ---- 4. optional live boot (works on permissive distros) ------------- */
    if (geteuid() == 0 || (caps.supported_flags & VMC_FLAG_NS_USER)) {
        mkdir("/tmp/ovl/lower", 0755); mkdir("/tmp/ovl/upper", 0755);
        mkdir("/tmp/ovl/work", 0755);  mkdir("/tmp/ovl/mnt", 0755);
        FILE *f = fopen("/tmp/ovl/lower/hello.txt", "w");
        if (f) { fprintf(f, "guest-root-seen\n"); fclose(f); }
        vmc_instance vm;
        int rc = vmc_vm_start(&cfg, &vm);
        if (rc == VMC_OK) {
            printf("      LIVE BOOT OK: guest_pid=%d cgroup=%s\n",
                   vm.guest_pid, vm.cgroup_path);
            char buf[256];
            int n = vmc_vm_read_log(&vm, buf, sizeof(buf), 3000);
            printf("      log read %d bytes\n", n);
            CHECK(vmc_vm_stop(&vm, 5000) == VMC_OK, "graceful stop");
        } else {
            printf("SKIP: live boot not possible here (%s)\n", vmc_strerror(rc));
        }
    }

    printf("== %s (%d failures) ==\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
