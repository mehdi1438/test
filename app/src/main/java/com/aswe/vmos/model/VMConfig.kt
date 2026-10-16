package com.aswe.vmos.model

/**
 * Static, user-editable description of a virtual machine — the "blueprint".
 * Persisted as JSON per VM (see [VMInstance.config]); handed to the native
 * layer via [com.aswe.vmos.jni.VMNativeConfig] which mirrors these fields
 * 1:1 onto the C struct `vmc_config` (app/src/main/jni/include/vm_container.h).
 *
 * Keep this class allocation-cheap and immutable: copy() on edit, never mutate.
 */
data class VMConfig(
    /** Stable identity; also used for directory names — keep filesystem-safe. */
    val id: String,
    /** Display name shown in the VM list UI. */
    val displayName: String = "Android VM",

    // ---------------------------------------------------------------- image
    /** Guest system image descriptor, e.g. "aosp-9-arm64-gapps-lite" v3. */
    val imageId: String = DEFAULT_IMAGE_ID,
    /** Absolute path of the extracted read-only system root (overlay lowerdir).
     *  Populated by ImageManager after unsquashfs/untar of the .vmi package. */
    val systemRootPath: String = "",
    /** Per-VM writable diff directory (overlay upperdir). */
    val dataDiffPath: String = "",
    /** Overlay workdir — MUST live on the same filesystem as [dataDiffPath]. */
    val overlayWorkPath: String = "",
    /** Where the merged overlay is mounted inside the private mount ns. */
    val mergedRootPath: String = "",

    // ------------------------------------------------------------ resources
    val resources: ResourceLimits = ResourceLimits(),

    // ------------------------------------------------------------- isolation
    /** Namespace/capability request mask; default = full isolation set.
     *  Values mirror VMC_FLAG_* in vm_container.h — do not renumber. */
    val isolationFlags: Long = IsolationFlag.DEFAULT,

    /** Host uid that guest uid 0 maps to (userns uid_map). The manager sets
     *  this to appUid+1 at boot time; persisted value is only a hint. */
    val guestRootUidOffset: Int = 0,
    /** Number of uids reserved for the guest (android app uid space is ~65k). */
    val guestUidCount: Int = 65_534,

    /** UTS hostname inside the guest. */
    val hostname: String = "vmos-guest",

    /** Screen geometry advertised to the guest SurfaceFlinger HAL (Phase 2). */
    val display: VirtualDisplaySpec = VirtualDisplaySpec(),

    /** Network mode. Phase 1 ships NAT_ONLY + AIRPLANE; TAP needs host CAP_NET_ADMIN. */
    val networkMode: NetworkMode = NetworkMode.NAT_ONLY,
    /** IPv4 CIDR of the isolated guest netns (veth0), e.g. "10.244.7.1/24". */
    val guestSubnetCidr: String = "10.244.7.1/24",

    /** Extra bind mounts injected into the guest (shared folders etc.). */
    val bindMounts: List<BindMount> = emptyList(),

    /** 0=quiet 1=info 2=verbose native logging. */
    val logLevel: Int = 1,

    /** Epoch millis of creation; drives sort order in the UI. */
    val createdAtEpochMs: Long = System.currentTimeMillis(),
) {
    init {
        require(id.matches(Regex("[A-Za-z0-9_-]{3,64}"))) {
            "VM id must be 3-64 chars of [A-Za-z0-9_-] (used as cgroup/dir name)"
        }
        require(resources.memoryLimitMb >= MIN_MEM_MB) {
            "Guest below ${MIN_MEM_MB}MB cannot boot Android 9+"
        }
        require(resources.cpuQuotaPercent in 1..800) { "cpu quota out of sane range" }
    }

    fun withEdits(block: Builder.() -> Unit): VMConfig =
        Builder(this).apply(block).build()

    /** Fluent builder mirroring the data class (Java-friendly escape hatch). */
    class Builder(src: VMConfig) {
        var id = src.id; var displayName = src.displayName
        var imageId = src.imageId; var systemRootPath = src.systemRootPath
        var dataDiffPath = src.dataDiffPath; var overlayWorkPath = src.overlayWorkPath
        var mergedRootPath = src.mergedRootPath
        var resources = src.resources; var isolationFlags = src.isolationFlags
        var guestRootUidOffset = src.guestRootUidOffset; var guestUidCount = src.guestUidCount
        var hostname = src.hostname; var display = src.display
        var networkMode = src.networkMode; var guestSubnetCidr = src.guestSubnetCidr
        var bindMounts = src.bindMounts; var logLevel = src.logLevel
        fun build() = VMConfig(id, displayName, imageId, systemRootPath, dataDiffPath,
            overlayWorkPath, mergedRootPath, resources, isolationFlags, guestRootUidOffset,
            guestUidCount, hostname, display, networkMode, guestSubnetCidr, bindMounts,
            logLevel, src.createdAtEpochMs)
    }

    companion object {
        const val DEFAULT_IMAGE_ID = "aosp-10-arm64-lite"
        const val MIN_MEM_MB = 512

        /** Sensible 2 CPU-core / 2 GB phone profile matching the spec example. */
        fun defaultProfile(vmId: String, storageRoot: String): VMConfig = VMConfig(
            id = vmId,
            displayName = "VM $vmId",
            systemRootPath = "$storageRoot/images/aosp-10-arm64-lite/system",
            dataDiffPath   = "$storageRoot/vms/$vmId/diff",
            overlayWorkPath = "$storageRoot/vms/$vmId/work",
            mergedRootPath  = "$storageRoot/vms/$vmId/merged",
            resources = ResourceLimits(cpuQuotaPercent = 50, memoryLimitMb = 2048),
        )
    }
}

/** cgroup-backed limits applied at clone() time (native `vmc_resources`). */
data class ResourceLimits(
    /** Percent of ONE cpu core, e.g. 50 => cfs_quota=50000/period=100000. */
    val cpuQuotaPercent: Int = 50,
    /** Hard memory cap in MB (memory.max / memory.limit_in_bytes). */
    val memoryLimitMb: Int = 2048,
    /** Swap ceiling; 0 disables swap entirely (recommended on flash storage). */
    val swapLimitMb: Int = 0,
    /** Fork-bomb guard. Android itself runs ~300 pids when idle. */
    val maxProcesses: Int = 512,
    /** cgroup blkio weight 10..1000 (lower = friendlier to host UI). */
    val blkioWeight: Int = 300,
)

/** Bit flags mirrored from vm_container.h — single source of truth lives there. */
object IsolationFlag {
    const val NS_PID    = 1L shl 0
    const val NS_NET    = 1L shl 1
    const val NS_MNT    = 1L shl 2
    const val NS_UTS    = 1L shl 3
    const val NS_IPC    = 1L shl 4
    const val NS_USER   = 1L shl 5
    const val NS_CGROUP = 1L shl 6
    const val NS_TIME   = 1L shl 7
    const val ROOTLESS  = 1L shl 8

    /** Full isolation set required by our security policy. */
    const val DEFAULT = NS_PID or NS_NET or NS_MNT or NS_UTS or NS_IPC or NS_USER or NS_CGROUP
}

/** Geometry pushed to the guest's virtual SurfaceFlinger (Phase 2 display link). */
data class VirtualDisplaySpec(
    val widthPx: Int = 1080,
    val heightPx: Int = 1920,
    val densityDpi: Int = 420,
    /** Target frames forwarded per second; 60 drains battery, 30 is plenty. */
    val targetFps: Int = 60,
)

enum class NetworkMode {
    /** Private netns + host-side NAT through the app's own uid socket relay. */
    NAT_ONLY,
    /** No connectivity at all (netns with lo only). */
    AIRPLANE,
    /** Bridge onto a host tap device — requires privileged helper (Phase 4). */
    TAP_BRIDGE,
}

/** One bind mount line, mirrored to native `vmc_bind`. */
data class BindMount(
    val sourceHostPath: String,
    val targetGuestPath: String,
    val readOnly: Boolean = false,
)
