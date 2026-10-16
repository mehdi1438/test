/*
 * vm_jni.c — JNI bridge between the Kotlin VM manager and libvmcontainer.
 *
 * Marshalling strategy: one flat Java object with public fields (VMNativeConfig)
 * read via GetFieldID once per call. Field names are a frozen ABI with
 * VMNativeConfig.kt — rename there, rename here, bump VMC_ABI_VERSION.
 */
#include <jni.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include "vm_container.h"

#define LOG_TAG "vm-jni"
#include "vm_log.h"

/* One live handle per slot; 8 concurrent VMs max is plenty for a phone. */
#define VMC_MAX_SLOTS 8
static vmc_instance g_slots[VMC_MAX_SLOTS];
static int g_slot_used[VMC_MAX_SLOTS];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static int slot_acquire(void) {
    int r = -1;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < VMC_MAX_SLOTS; i++)
        if (!g_slot_used[i]) { g_slot_used[i] = 1; r = i; break; }
    pthread_mutex_unlock(&g_lock);
    return r;
}
static void slot_release(int s) {
    pthread_mutex_lock(&g_lock);
    if (s >= 0 && s < VMC_MAX_SLOTS) g_slot_used[s] = 0;
    pthread_mutex_unlock(&g_lock);
}

/* jstring -> fixed char buffer. Returns JNI_OK/JNI_ERR. */
static jint jstr2buf(JNIEnv *env, jobject obj, const char *name,
                     char *out, size_t outlen) {
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env, cls, name, "Ljava/lang/String;");
    if (!fid) { (*env)->ExceptionClear(env); return JNI_ERR; }
    jstring js = (jstring)(*env)->GetObjectField(env, obj, fid);
    if (!js) { out[0] = '\0'; return JNI_OK; }
    const char *c = (*env)->GetStringUTFChars(env, js, NULL);
    snprintf(out, outlen, "%s", c ? c : "");
    if (c) (*env)->ReleaseStringUTFChars(env, js, c);
    return JNI_OK;
}

static jint jlongField(JNIEnv *env, jobject obj, const char *name, long *out) {
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env, cls, name, "J");
    if (!fid) { (*env)->ExceptionClear(env); return JNI_ERR; }
    *out = (long)(*env)->GetLongField(env, obj, fid);
    return JNI_OK;
}

static jint jintField(JNIEnv *env, jobject obj, const char *name, int *out) {
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID fid = (*env)->GetFieldID(env, cls, name, "I");
    if (!fid) { (*env)->ExceptionClear(env); return JNI_ERR; }
    *out = (*env)->GetIntField(env, obj, fid);
    return JNI_OK;
}

/* ----------------------------------------------------------- native methods */

JNIEXPORT jint JNICALL
Java_com_aswe_vmos_jni_NativeBridge_probeCaps(JNIEnv *env, jclass clazz,
                                              jobject capsObj) {
    (void)env; (void)clazz; (void)capsObj;
    /* Caps are returned as parallel primitives via the simpler API below to
     * avoid a second marshalling struct in Phase 1. */
    vmc_caps c;
    int rc = vmc_probe_caps(&c);
    return rc;
}

JNIEXPORT jlong JNICALL
Java_com_aswe_vmos_jni_NativeBridge_supportedFlags(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    vmc_caps c;
    if (vmc_probe_caps(&c) != VMC_OK) return 0;
    return (jlong)c.supported_flags;
}

JNIEXPORT jboolean JNICALL
Java_com_aswe_vmos_jni_NativeBridge_isCgroupV2(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    vmc_caps c;
    if (vmc_probe_caps(&c) != VMC_OK) return JNI_FALSE;
    return c.cgroup_v2 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_aswe_vmos_jni_NativeBridge_kernelRelease(JNIEnv *env, jclass clazz) {
    (void)clazz;
    vmc_caps c;
    if (vmc_probe_caps(&c) != VMC_OK)
        return (*env)->NewStringUTF(env, "unknown");
    return (*env)->NewStringUTF(env, c.kernel_release);
}

JNIEXPORT jstring JNICALL
Java_com_aswe_vmos_jni_NativeBridge_strerror(JNIEnv *env, jclass clazz, jint err) {
    (void)clazz;
    return (*env)->NewStringUTF(env, vmc_strerror((int)err));
}

/* cfgObj must be com.aswe.vmos.jni.VMNativeConfig (flat field mirror of
 * vmc_config). */
JNIEXPORT jint JNICALL
Java_com_aswe_vmos_jni_NativeBridge_vmStart(JNIEnv *env, jclass clazz, jobject cfgObj) {
    (void)clazz;
    if (!cfgObj) return VMC_ERR_INVAL;

    vmc_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.abi_version = VMC_ABI_VERSION;

    if (jstr2buf(env, cfgObj, "vmName",      cfg.vm_name,  sizeof(cfg.vm_name))  != JNI_OK ||
        jstr2buf(env, cfgObj, "lowerdir",    cfg.overlay.lowerdir,   sizeof(cfg.overlay.lowerdir))   != JNI_OK ||
        jstr2buf(env, cfgObj, "upperdir",    cfg.overlay.upperdir,   sizeof(cfg.overlay.upperdir))   != JNI_OK ||
        jstr2buf(env, cfgObj, "workdir",     cfg.overlay.workdir,    sizeof(cfg.overlay.workdir))    != JNI_OK ||
        jstr2buf(env, cfgObj, "mergedDir",   cfg.overlay.merged_dir, sizeof(cfg.overlay.merged_dir)) != JNI_OK ||
        jstr2buf(env, cfgObj, "hostname",    cfg.hostname, sizeof(cfg.hostname)) != JNI_OK) {
        LOGE("JNI field lookup failed — VMNativeConfig ABI drift?");
        return VMC_ERR_INVAL;
    }

    long flags = 0; int uidOffset = 0, uidCount = 0;
    int cpuPct = 50, memMb = 2048, pidsMax = 512, swapMb = 0, blkio = 300, logLevel = 1;
    if (jlongField(env, cfgObj, "flags", &flags) != JNI_OK ||
        jintField(env, cfgObj, "uidOffset", &uidOffset) != JNI_OK ||
        jintField(env, cfgObj, "uidCount", &uidCount) != JNI_OK ||
        jintField(env, cfgObj, "cpuQuotaPercent", &cpuPct) != JNI_OK ||
        jintField(env, cfgObj, "memoryLimitMb", &memMb) != JNI_OK ||
        jintField(env, cfgObj, "pidsMax", &pidsMax) != JNI_OK ||
        jintField(env, cfgObj, "swapLimitMb", &swapMb) != JNI_OK ||
        jintField(env, cfgObj, "blkioWeight", &blkio) != JNI_OK ||
        jintField(env, cfgObj, "logLevel", &logLevel) != JNI_OK) {
        return VMC_ERR_INVAL;
    }
    cfg.flags = (uint64_t)flags;
    cfg.uid_offset = (uint32_t)uidOffset;
    cfg.uid_count  = (uint32_t)(uidCount > 0 ? uidCount : 65534);
    cfg.res.cpu_quota_percent = (uint32_t)cpuPct;
    cfg.res.mem_limit_mb      = (uint32_t)memMb;
    cfg.res.pids_max          = (uint32_t)pidsMax;
    cfg.res.mem_swap_limit_mb = (uint32_t)swapMb;
    cfg.res.blkio_weight      = (uint32_t)blkio;
    cfg.log_level             = (uint32_t)logLevel;
    snprintf(cfg.init_path, sizeof(cfg.init_path), "/init");

    int slot = slot_acquire();
    if (slot < 0) return VMC_ERR_NOMEM;

    int rc = vmc_vm_start(&cfg, &g_slots[slot]);
    if (rc != VMC_OK) {
        slot_release(slot);
        LOGE("vm_start('%s') failed: %s", cfg.vm_name, vmc_strerror(rc));
        return rc;
    }
    LOGI("VM started in slot %d pid=%d", slot, g_slots[slot].guest_pid);
    /* encode slot+1 so Kotlin can distinguish from error codes (<0) */
    return slot + 1;
}

JNIEXPORT jint JNICALL
Java_com_aswe_vmos_jni_NativeBridge_vmStop(JNIEnv *env, jclass clazz,
                                           jint slot1, jint timeoutMs) {
    (void)env; (void)clazz;
    int slot = (int)slot1 - 1;
    if (slot < 0 || slot >= VMC_MAX_SLOTS || !g_slot_used[slot])
        return VMC_ERR_STATE;
    int rc = vmc_vm_stop(&g_slots[slot], (uint32_t)(timeoutMs > 0 ? timeoutMs : 8000));
    slot_release(slot);
    return rc;
}

JNIEXPORT jint JNICALL
Java_com_aswe_vmos_jni_NativeBridge_vmKillAll(JNIEnv *env, jclass clazz, jint slot1) {
    (void)env; (void)clazz;
    int slot = (int)slot1 - 1;
    if (slot < 0 || slot >= VMC_MAX_SLOTS || !g_slot_used[slot])
        return VMC_ERR_STATE;
    return vmc_vm_kill_all(&g_slots[slot]);
}

/** Returns guest pid (>0), or negative VMC error, or 0 == exited. */
JNIEXPORT jint JNICALL
Java_com_aswe_vmos_jni_NativeBridge_vmPoll(JNIEnv *env, jclass clazz, jint slot1) {
    (void)env; (void)clazz;
    int slot = (int)slot1 - 1;
    if (slot < 0 || slot >= VMC_MAX_SLOTS || !g_slot_used[slot])
        return VMC_ERR_STATE;
    vmc_vm_poll(&g_slots[slot]);
    if (g_slots[slot].state == VMC_STATE_STOPPED ||
        g_slots[slot].state == VMC_STATE_FAILED) {
        slot_release(slot);
        return 0;
    }
    return g_slots[slot].guest_pid;
}

/** Pull up to `max` bytes of guest console/log lines; blocks up to timeoutMs.
 *  Returns byte count, 0 on EOF/exit, negative on error. */
JNIEXPORT jint JNICALL
Java_com_aswe_vmos_jni_NativeBridge_vmReadLog(JNIEnv *env, jclass clazz,
                                              jint slot1, jbyteArray bufArr,
                                              jint max, jint timeoutMs) {
    (void)clazz;
    int slot = (int)slot1 - 1;
    if (slot < 0 || slot >= VMC_MAX_SLOTS || !g_slot_used[slot])
        return VMC_ERR_STATE;
    if (!bufArr || max <= 0) return VMC_ERR_INVAL;
    jbyte *tmp = (jbyte*)(*env)->GetPrimitiveArrayCritical(env, bufArr, NULL);
    if (!tmp) return VMC_ERR_NOMEM;
    int n = vmc_vm_read_log(&g_slots[slot], (char *)tmp, (size_t)max, (int)timeoutMs);
    (*env)->ReleasePrimitiveArrayCritical(env, bufArr, tmp, 0);
    return n;
}

