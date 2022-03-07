#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1579.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126040);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/20 11:24:24");

  script_cve_id("CVE-2013-4343", "CVE-2018-7191", "CVE-2019-10124", "CVE-2019-11085", "CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479", "CVE-2019-11487", "CVE-2019-11833", "CVE-2019-12380", "CVE-2019-12382", "CVE-2019-12456", "CVE-2019-12818", "CVE-2019-12819", "CVE-2019-3846", "CVE-2019-5489");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-1579) (SACK Panic) (SACK Slowness)");
  script_summary(english:"Check for the openSUSE-2019-1579 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 15.0 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2019-11477: A sequence of SACKs may have been
    crafted by a remote attacker such that one can trigger
    an integer overflow, leading to a kernel panic.
    (bsc#1137586).

  - CVE-2019-11478: It was possible to send a crafted
    sequence of SACKs which would fragment the TCP
    retransmission queue. A remote attacker may have been
    able to further exploit the fragmented queue to cause an
    expensive linked-list walk for subsequent SACKs received
    for that same TCP connection. (bsc#1137586)

  - CVE-2019-11479: It was possible to send a crafted
    sequence of SACKs which would fragment the RACK send
    map. A remote attacker may be able to further exploit
    the fragmented send map to cause an expensive
    linked-list walk for subsequent SACKs received for that
    same TCP connection. This would have resulted in excess
    resource consumption due to low mss values.
    (bsc#1137586)

  - CVE-2019-12819: The function __mdiobus_register() in
    drivers/net/phy/mdio_bus.c calls put_device(), which
    will trigger a fixed_mdio_bus_init use-after-free. This
    will cause a denial of service (bnc#1138291).

  - CVE-2019-12818: The nfc_llcp_build_tlv function in
    net/nfc/llcp_commands.c may return NULL. If the caller
    did not check for this, it will trigger a NULL pointer
    dereference. This will cause denial of service. This
    affects nfc_llcp_build_gb in net/nfc/llcp_core.c
    (bnc#1138293).

  - CVE-2019-12456: local users could cause a denial of
    service or possibly have unspecified other impact by
    changing the value of ioc_number between two kernel
    reads of that value, aka a 'double fetch' vulnerability.
    (bnc#1136922)

  - CVE-2019-12380: phys_efi_set_virtual_address_map in
    arch/x86/platform/efi/efi.c and efi_call_phys_prolog in
    arch/x86/platform/efi/efi_64.c mishandle memory
    allocation failures (bnc#1136598).

  - CVE-2019-3846: A flaw that allowed an attacker to
    corrupt memory and possibly escalate privileges was
    found in the mwifiex kernel module while connecting to a
    malicious wireless network (bnc#1136424).

  - CVE-2019-10124: An attacker could exploit an issue in
    the hwpoison implementation to cause a denial of service
    (BUG). (bsc#1130699)

  - CVE-2019-12382: An issue was discovered in
    drm_load_edid_firmware in
    drivers/gpu/drm/drm_edid_load.c. There was an unchecked
    kstrdup of fwstr, which might allow an attacker to cause
    a denial of service (NULL pointer dereference and system
    crash) (bnc#1136586).

  - CVE-2019-11487: The Linux kernel before 5.1-rc5 allowed
    page->_refcount reference count overflow, with resultant
    use-after-free issues, if about 140 GiB of RAM exists.
    This is related to fs/fuse/dev.c, fs/pipe.c,
    fs/splice.c, include/linux/mm.h,
    include/linux/pipe_fs_i.h, kernel/trace/trace.c,
    mm/gup.c, and mm/hugetlb.c. It can occur with FUSE
    requests (bnc#1133190).

  - CVE-2019-5489: The mincore() implementation in
    mm/mincore.c allowed local attackers to observe page
    cache access patterns of other processes on the same
    system, potentially allowing sniffing of secret
    information. (Fixing this affects the output of the
    fincore program.) Limited remote exploitation may be
    possible, as demonstrated by latency differences in
    accessing public files from an Apache HTTP Server
    (bnc#1120843).

  - CVE-2019-11833: fs/ext4/extents.c did not zero out the
    unused memory region in the extent tree block, which
    might allow local users to obtain sensitive information
    by reading uninitialized data in the filesystem
    (bnc#1135281).

  - CVE-2018-7191: In the tun subsystem dev_get_valid_name
    is not called before register_netdevice. This allowed
    local users to cause a denial of service (NULL pointer
    dereference and panic) via an ioctl(TUNSETIFF) call with
    a dev name containing a / character. This is similar to
    CVE-2013-4343 (bnc#1135603).

  - CVE-2019-11085: Insufficient input validation in Kernel
    Mode Driver in Intel(R) i915 Graphics may have allowed
    an authenticated user to potentially enable escalation
    of privilege via local access (bnc#1135278).

The following non-security bugs were fixed :

  - 9p locks: add mount option for lock retry interval
    (bsc#1051510).

  - ACPI: Add Hygon Dhyana support ().

  - ACPI: button: reinitialize button state upon resume
    (bsc#1051510).

  - ACPICA: AML interpreter: add region addresses in global
    list during initialization (bsc#1051510).

  - ACPICA: Namespace: remove address node from global list
    after method termination (bsc#1051510).

  - ACPI: fix menuconfig presentation of ACPI submenu
    (bsc#1117158).

  - ACPI / property: fix handling of data_nodes in
    acpi_get_next_subnode() (bsc#1051510).

  - ACPI / utils: Drop reference in test for device presence
    (bsc#1051510).

  - ALSA: firewire-motu: fix destruction of data for
    isochronous resources (bsc#1051510).

  - ALSA: hda/realtek - Avoid superfluous COEF EAPD setups
    (bsc#1051510).

  - ALSA: hda/realtek - Corrected fixup for System76 Gazelle
    (gaze14) (bsc#1051510).

  - ALSA: hda/realtek - Fix for Lenovo B50-70 inverted
    internal microphone bug (bsc#1051510).

  - ALSA: hda/realtek - Fixup headphone noise via runtime
    suspend (bsc#1051510).

  - ALSA: hda/realtek - Improve the headset mic for Acer
    Aspire laptops (bsc#1051510).

  - ALSA: hda/realtek - Set default power save node to 0
    (bsc#1051510).

  - ALSA: hda/realtek - Update headset mode for ALC256
    (bsc#1051510).

  - ALSA: hda - Use a macro for snd_array iteration loops
    (bsc#1051510).

  - ALSA: oxfw: allow PCM capture for Stanton SCS.1m
    (bsc#1051510).

  - appletalk: Fix compile regression (bsc#1051510).

  - appletalk: Fix use-after-free in atalk_proc_exit
    (bsc#1051510).

  - arch: arm64: acpi: KABI ginore includes (bsc#1117158
    bsc#1134671).

  - arm64: acpi: fix alignment fault in accessing ACPI
    (bsc#1117158).

  - arm64: Export save_stack_trace_tsk() (jsc#SLE-4214).

  - arm64: fix ACPI dependencies (bsc#1117158).

  - arm64, mm, efi: Account for GICv3 LPI tables in static
    memblock reserve table (bsc#1117158).

  - arm64/x86: Update config files. Use
    CONFIG_ARCH_SUPPORTS_ACPI

  - arm: 8824/1: fix a migrating irq bug when hotplug cpu
    (bsc#1051510).

  - arm: 8833/1: Ensure that NEON code always compiles with
    Clang (bsc#1051510).

  - arm: 8839/1: kprobe: make patch_lock a raw_spinlock_t
    (bsc#1051510).

  - arm: 8840/1: use a raw_spinlock_t in unwind
    (bsc#1051510).

  - arm: avoid Cortex-A9 livelock on tight dmb loops
    (bsc#1051510).

  - arm: imx6q: cpuidle: fix bug that CPU might not wake up
    at expected time (bsc#1051510).

  - arm: iop: do not use using 64-bit DMA masks
    (bsc#1051510).

  - arm: OMAP2+: fix lack of timer interrupts on CPU1 after
    hotplug (bsc#1051510).

  - arm: OMAP2+: Variable 'reg' in function
    omap4_dsi_mux_pads() could be uninitialized
    (bsc#1051510).

  - arm: orion: do not use using 64-bit DMA masks
    (bsc#1051510).

  - arm: pxa: ssp: unneeded to free devm_ allocated data
    (bsc#1051510).

  - arm: s3c24xx: Fix boolean expressions in
    osiris_dvs_notify (bsc#1051510).

  - arm: samsung: Limit SAMSUNG_PM_CHECK config option to
    non-Exynos platforms (bsc#1051510).

  - ASoC: cs42xx8: Add regcache mask dirty (bsc#1051510).

  - ASoC: eukrea-tlv320: fix a leaked reference by adding
    missing of_node_put (bsc#1051510).

  - ASoC: fsl_asrc: Fix the issue about unsupported rate
    (bsc#1051510).

  - ASoC: fsl_sai: Update is_slave_mode with correct value
    (bsc#1051510).

  - ASoC: fsl_utils: fix a leaked reference by adding
    missing of_node_put (bsc#1051510).

  - ASoC: hdmi-codec: unlock the device on startup errors
    (bsc#1051510).

  - backlight: lm3630a: Return 0 on success in update_status
    functions (bsc#1051510).

  - batman-adv: allow updating DAT entry timeouts on
    incoming ARP Replies (bsc#1051510).

  - blk-mq: fix hang caused by freeze/unfreeze sequence
    (bsc#1128432).

  - block: do not leak memory in bio_copy_user_iov()
    (bsc#1135309).

  - block: Do not revalidate bdev of hidden gendisk
    (bsc#1120091).

  - block: fix the return errno for direct IO (bsc#1135320).

  - block: fix use-after-free on gendisk (bsc#1135312).

  - Bluetooth: Check key sizes only when Secure Simple
    Pairing is enabled (bsc#1135556).

  - bnxt_en: Free short FW command HWRM memory in error path
    in bnxt_init_one() (bsc#1050242).

  - bnxt_en: Improve multicast address setup logic
    (networking-stable-19_05_04).

  - bnxt_en: Improve RX consumer index validity check
    (networking-stable-19_04_10).

  - bnxt_en: Reset device on RX buffer errors
    (networking-stable-19_04_10).

  - bonding: fix event handling for stacked bonds
    (networking-stable-19_04_19).

  - bpf: add map_lookup_elem_sys_only for lookups from
    syscall side (bsc#1083647).

  - bpf: Add missed newline in verifier verbose log
    (bsc#1056787).

  - bpf, lru: avoid messing with eviction heuristics upon
    syscall lookup (bsc#1083647).

  - brcmfmac: convert dev_init_lock mutex to completion
    (bsc#1051510).

  - brcmfmac: fix missing checks for kmemdup (bsc#1051510).

  - brcmfmac: fix Oops when bringing up interface during USB
    disconnect (bsc#1051510).

  - brcmfmac: fix race during disconnect when USB completion
    is in progress (bsc#1051510).

  - brcmfmac: fix WARNING during USB disconnect in case of
    unempty psq (bsc#1051510).

  - btrfs: delayed-ref: Use btrfs_ref to refactor
    btrfs_add_delayed_data_ref() (bsc#1063638 bsc#1128052
    bsc#1108838).

  - btrfs: delayed-ref: Use btrfs_ref to refactor
    btrfs_add_delayed_tree_ref() (bsc#1063638 bsc#1128052
    bsc#1108838).

  - btrfs: do not allow trimming when a fs is mounted with
    the nologreplay option (bsc#1135758).

  - btrfs: do not double unlock on error in btrfs_punch_hole
    (bsc#1136881).

  - btrfs: extent-tree: Fix a bug that btrfs is unable to
    add pinned bytes (bsc#1063638 bsc#1128052 bsc#1108838).

  - btrfs: extent-tree: Use btrfs_ref to refactor
    add_pinned_bytes() (bsc#1063638 bsc#1128052
    bsc#1108838).

  - btrfs: extent-tree: Use btrfs_ref to refactor
    btrfs_free_extent() (bsc#1063638 bsc#1128052
    bsc#1108838).

  - btrfs: extent-tree: Use btrfs_ref to refactor
    btrfs_inc_extent_ref() (bsc#1063638 bsc#1128052
    bsc#1108838).

  - btrfs: fix fsync not persisting changed attributes of a
    directory (bsc#1137151).

  - btrfs: fix race between ranged fsync and writeback of
    adjacent ranges (bsc#1136477).

  - btrfs: fix race updating log root item during fsync
    (bsc#1137153).

  - btrfs: fix wrong ctime and mtime of a directory after
    log replay (bsc#1137152).

  - btrfs: improve performance on fsync of files with
    multiple hardlinks (bsc#1123454).

  - btrfs: qgroup: Check bg while resuming relocation to
    avoid NULL pointer dereference (bsc#1134806).

  - btrfs: qgroup: Do not scan leaf if we're modifying reloc
    tree (bsc#1063638 bsc#1128052 bsc#1108838).

  - btrfs: reloc: Also queue orphan reloc tree for cleanup
    to avoid BUG_ON() (bsc#1133612).

  - btrfs: send, flush dellaloc in order to avoid data loss
    (bsc#1133320).

  - btrfs: tree-checker: detect file extent items with
    overlapping ranges (bsc#1136478).

  - chardev: add additional check for minor range overlap
    (bsc#1051510).

  - CIFS: keep FileInfo handle live during oplock break
    (bsc#1106284, bsc#1131565).

  - configfs: fix possible use-after-free in
    configfs_register_group (bsc#1051510).

  - configfs: Fix use-after-free when accessing sd->s_dentry
    (bsc#1051510).

  - cpufreq: Add Hygon Dhyana support ().

  - cpufreq: AMD: Ignore the check for ProcFeedback in ST/CZ
    ().

  - crypto: caam - fix caam_dump_sg that iterates through
    scatterlist (bsc#1051510).

  - crypto: vmx - CTR: always increment IV as quadword
    (bsc#1051510).

  - crypto: vmx - ghash: do nosimd fallback manually
    (bsc#1135661, bsc#1137162).

  - crypto: vmx - return correct error code on failed setkey
    (bsc#1135661, bsc#1137162).

  - dccp: do not use ipv6 header for ipv4 flow
    (networking-stable-19_03_28).

  - dccp: Fix memleak in __feat_register_sp (bsc#1051510).

  - debugfs: fix use-after-free on symlink traversal
    (bsc#1051510).

  - devres: Align data[] to ARCH_KMALLOC_MINALIGN
    (bsc#1051510).

  - docs: Fix conf.py for Sphinx 2.0 (bsc#1135642).

  - Documentation: Add MDS vulnerability documentation
    (bsc#1135642).

  - Documentation: Correct the possible MDS sysfs values
    (bsc#1135642).

  - drbd: Avoid Clang warning about pointless switch
    statment (bsc#1051510).

  - drbd: disconnect, if the wrong UUIDs are attached on a
    connected peer (bsc#1051510).

  - drbd: narrow rcu_read_lock in drbd_sync_handshake
    (bsc#1051510).

  - drbd: skip spurious timeout (ping-timeo) when failing
    promote (bsc#1051510).

  - drivers: acpi: add dependency of EFI for arm64
    (bsc#1117158).

  - drm/amdgpu: fix old fence check in amdgpu_fence_emit
    (bsc#1051510).

  - drm/bridge: adv7511: Fix low refresh rate selection
    (bsc#1051510).

  - drm/drv: Hold ref on parent device during drm_device
    lifetime (bsc#1051510).

  - drm/etnaviv: lock MMU while dumping core (bsc#1113722)

  - drm/gma500/cdv: Check vbt config bits when detecting
    lvds panels (bsc#1051510).

  - drm/i915: Disable LP3 watermarks on all SNB machines
    (bsc#1051510).

  - drm/i915: Downgrade Gen9 Plane WM latency error
    (bsc#1051510).

  - drm/i915/fbc: disable framebuffer compression on
    GeminiLake (bsc#1051510).

  - drm/i915/gvt: add 0x4dfc to gen9 save-restore list
    (bsc#1113722)

  - drm/i915/gvt: do not let TRTTE and 0x4dfc write
    passthrough to hardware (bsc#1051510).

  - drm/i915/gvt: Fix cmd length of VEB_DI_IECP
    (bsc#1113722)

  - drm/i915/gvt: refine ggtt range validation (bsc#1113722)

  - drm/i915/gvt: Tiled Resources mmios are in-context mmios
    for gen9+ (bsc#1113722)

  - drm/i915/perf: fix whitelist on Gen10+ (bsc#1051510).

  - drm/i915/sdvo: Implement proper HDMI audio support for
    SDVO (bsc#1051510).

  - drm/imx: do not skip DP channel disable for background
    plane (bsc#1051510).

  - drm/nouveau/disp/dp: respect sink limits when selecting
    failsafe link configuration (bsc#1051510).

  - drm/nouveau/i2c: Disable i2c bus access after ->fini()
    (bsc#1113722)

  - drm/radeon: prefer lower reference dividers
    (bsc#1051510).

  - drm/rockchip: fix for mailbox read validation
    (bsc#1051510).

  - drm/vmwgfx: Do not send drm sysfs hotplug events on
    initial master set (bsc#1051510).

  - drm/vmwgfx: integer underflow in vmw_cmd_dx_set_shader()
    leading to an invalid read (bsc#1051510).

  - drm/vmwgfx: NULL pointer dereference from
    vmw_cmd_dx_view_define() (bsc#1113722)

  - drm: Wake up next in drm_read() chain if we are forced
    to putback the event (bsc#1051510).

  - dt-bindings: clock: r8a7795: Remove CSIREF clock
    (bsc#1120902).

  - dt-bindings: clock: r8a7796: Remove CSIREF clock
    (bsc#1120902).

  - dt-bindings: net: Add binding for the external clock for
    TI WiLink (bsc#1085535).

  - dt-bindings: rtc: sun6i-rtc: Fix register range in
    example (bsc#1120902).

  - EDAC, amd64: Add Hygon Dhyana support ().

  - efi: add API to reserve memory persistently across kexec
    reboot (bsc#1117158).

  - efi/arm: Defer persistent reservations until after
    paging_init() (bsc#1117158).

  - efi/arm: Do not mark ACPI reclaim memory as
    MEMBLOCK_NOMAP (bsc#1117158 bsc#1115688 bsc#1120566).

  - efi/arm: libstub: add a root memreserve config table
    (bsc#1117158).

  - efi/arm: map UEFI memory map even w/o runtime services
    enabled (bsc#1117158).

  - efi/arm: preserve early mapping of UEFI memory map
    longer for BGRT (bsc#1117158).

  - efi/arm: Revert 'Defer persistent reservations until
    after paging_init()' (bsc#1117158).

  - efi/arm: Revert deferred unmap of early memmap mapping
    (bsc#1117158).

  - efi: honour memory reservations passed via a linux
    specific config table (bsc#1117158).

  - efi: Permit calling efi_mem_reserve_persistent() from
    atomic context (bsc#1117158).

  - efi: Permit multiple entries in persistent memreserve
    data structure (bsc#1117158).

  - efi: Prevent GICv3 WARN() by mapping the memreserve
    table before first use (bsc#1117158).

  - efi: Reduce the amount of memblock reservations for
    persistent allocations (bsc#1117158).

  - ext4: actually request zeroing of inode table after grow
    (bsc#1135315).

  - ext4: avoid panic during forced reboot due to aborted
    journal (bsc#1126356).

  - ext4: fix data corruption caused by overlapping
    unaligned and aligned IO (bsc#1136428).

  - ext4: fix ext4_show_options for file systems w/o journal
    (bsc#1135316).

  - ext4: fix use-after-free race with
    debug_want_extra_isize (bsc#1135314).

  - ext4: make sanity check in mballoc more strict
    (bsc#1136439).

  - ext4: wait for outstanding dio during truncate in
    nojournal mode (bsc#1136438).

  - extcon: arizona: Disable mic detect if running when
    driver is removed (bsc#1051510).

  - fbdev: fix divide error in fb_var_to_videomode
    (bsc#1113722)

  - fbdev: fix WARNING in __alloc_pages_nodemask bug
    (bsc#1113722)

  - firmware: efi: factor out mem_reserve (bsc#1117158
    bsc#1134671).

  - fix rtnh_ok() (git-fixes).

  - fs/sync.c: sync_file_range(2) may use WB_SYNC_ALL
    writeback (bsc#1136432).

  - fs/writeback.c: use rcu_barrier() to wait for inflight
    wb switches going into workqueue when umount
    (bsc#1136435).

  - ftrace/x86_64: Emulate call function while updating in
    breakpoint handler (bsc#1099658).

  - fuse: fallocate: fix return with locked inode
    (bsc#1051510).

  - fuse: fix writepages on 32bit (bsc#1051510).

  - fuse: honor RLIMIT_FSIZE in fuse_file_fallocate
    (bsc#1051510).

  - genetlink: Fix a memory leak on error path
    (networking-stable-19_03_28).

  - gpio: fix gpio-adp5588 build errors (bsc#1051510).

  - gpio: Remove obsolete comment about gpiochip_free_hogs()
    usage (bsc#1051510).

  - gpu: ipu-v3: dp: fix CSC handling (bsc#1051510).

  - HID: input: add mapping for Expose/Overview key
    (bsc#1051510).

  - HID: input: add mapping for keyboard Brightness
    Up/Down/Toggle keys (bsc#1051510).

  - HID: input: add mapping for 'Toggle Display' key
    (bsc#1051510).

  - HID: input: fix a4tech horizontal wheel custom usage
    (bsc#1137429).

  - HID: logitech-hidpp: change low battery level threshold
    from 31 to 30 percent (bsc#1051510).

  - HID: logitech-hidpp: use RAP instead of FAP to get the
    protocol version (bsc#1051510).

  - HID: wacom: Add ability to provide explicit battery
    status info (bsc#1051510).

  - HID: wacom: Add support for 3rd generation Intuos BT
    (bsc#1051510).

  - HID: wacom: Add support for Pro Pen slim (bsc#1051510).

  - HID: wacom: convert Wacom custom usages to standard HID
    usages (bsc#1051510).

  - HID: wacom: Correct button numbering 2nd-gen Intuos Pro
    over Bluetooth (bsc#1051510).

  - HID: wacom: Do not report anything prior to the tool
    entering range (bsc#1051510).

  - HID: wacom: Do not set tool type until we're in range
    (bsc#1051510).

  - HID: wacom: fix mistake in printk (bsc#1051510).

  - HID: wacom: generic: add the 'Report Valid' usage
    (bsc#1051510).

  - HID: wacom: generic: Ignore HID_DG_BATTERYSTRENTH == 0
    (bsc#1051510).

  - HID: wacom: generic: Leave tool in prox until it
    completely leaves sense (bsc#1051510).

  - HID: wacom: generic: Refactor generic battery handling
    (bsc#1051510).

  - HID: wacom: generic: Report AES battery information
    (bsc#1051510).

  - HID: wacom: generic: Reset events back to zero when pen
    leaves (bsc#1051510).

  - HID: wacom: generic: Scale battery capacity measurements
    to percentages (bsc#1051510).

  - HID: wacom: generic: Send BTN_STYLUS3 when both barrel
    switches are set (bsc#1051510).

  - HID: wacom: generic: Send BTN_TOOL_PEN in prox once the
    pen enters range (bsc#1051510).

  - HID: wacom: generic: Support multiple tools per report
    (bsc#1051510).

  - HID: wacom: generic: Use generic codepath terminology in
    wacom_wac_pen_report (bsc#1051510).

  - HID: wacom: Mark expected switch fall-through
    (bsc#1051510).

  - HID: wacom: Move handling of HID quirks into a dedicated
    function (bsc#1051510).

  - HID: wacom: Move HID fix for AES serial number into
    wacom_hid_usage_quirk (bsc#1051510).

  - HID: wacom: Properly handle AES serial number and tool
    type (bsc#1051510).

  - HID: wacom: Queue events with missing type/serial data
    for later processing (bsc#1051510).

  - HID: wacom: Remove comparison of u8 mode with zero and
    simplify (bsc#1051510).

  - HID: wacom: Replace touch_max fixup code with static
    touch_max definitions (bsc#1051510).

  - HID: wacom: Send BTN_TOUCH in response to INTUOSP2_BT
    eraser contact (bsc#1051510).

  - HID: wacom: Support 'in range' for Intuos/Bamboo tablets
    where possible (bsc#1051510).

  - HID: Wacom: switch Dell canvas into highres mode
    (bsc#1051510).

  - HID: wacom: Sync INTUOSP2_BT touch state after each
    frame if necessary (bsc#1051510).

  - HID: wacom: wacom_wac_collection() is local to
    wacom_wac.c (bsc#1051510).

  - HID: wacom: Work around HID descriptor bug in DTK-2451
    and DTH-2452 (bsc#1051510).

  - hwmon: (core) add thermal sensors only if dev->of_node
    is present (bsc#1051510).

  - hwmon: (pmbus/core) Treat parameters as paged if on
    multiple pages (bsc#1051510).

  - hwrng: omap - Set default quality (bsc#1051510).

  - i2c: dev: fix potential memory leak in i2cdev_ioctl_rdwr
    (bsc#1051510).

  - i2c: i801: Add support for Intel Comet Lake
    (jsc#SLE-5331).

  - ibmvnic: Add device identification to requested IRQs
    (bsc#1137739).

  - ibmvnic: Do not close unopened driver during reset
    (bsc#1137752).

  - ibmvnic: Fix unchecked return codes of memory
    allocations (bsc#1137752).

  - ibmvnic: Refresh device multicast list after reset
    (bsc#1137752).

  - ibmvnic: remove set but not used variable 'netdev'
    (bsc#1137739).

  - igmp: fix incorrect unsolicit report count when join
    group (git-fixes).

  - iio: adc: xilinx: fix potential use-after-free on remove
    (bsc#1051510).

  - iio: ad_sigma_delta: Properly handle SPI bus locking vs
    CS assertion (bsc#1051510).

  - iio: common: ssp_sensors: Initialize calculated_time in
    ssp_common_process_data (bsc#1051510).

  - iio: hmc5843: fix potential NULL pointer dereferences
    (bsc#1051510).

  - indirect call wrappers: helpers to speed-up indirect
    calls of builtin (bsc#1124503).

  - inetpeer: fix uninit-value in inet_getpeer (git-fixes).

  - Input: elan_i2c - add hardware ID for multiple Lenovo
    laptops (bsc#1051510).

  - Input: synaptics-rmi4 - fix possible double free
    (bsc#1051510).

  - iommu/arm-smmu-v3: Abort all transactions if SMMU is
    enabled in kdump kernel (bsc#1117158).

  - iommu/arm-smmu-v3: Do not disable SMMU in kdump kernel
    (bsc#1117158 bsc#1134671).

  - ip6_tunnel: collect_md xmit: Use ip_tunnel_key's
    provided src address (git-fixes).

  - ip6_tunnel: Match to ARPHRD_TUNNEL6 for dev type
    (networking-stable-19_04_10).

  - ipconfig: Correctly initialise ic_nameservers
    (bsc#1051510).

  - ip_gre: fix parsing gre header in ipgre_err (git-fixes).

  - ip_tunnel: Fix name string concatenate in
    __ip_tunnel_create() (git-fixes).

  - ipv4: add sanity checks in ipv4_link_failure()
    (git-fixes).

  - ipv4: Define __ipv4_neigh_lookup_noref when CONFIG_INET
    is disabled (git-fixes).

  - ipv4: ensure rcu_read_lock() in ipv4_link_failure()
    (networking-stable-19_04_19).

  - ipv4: ip_do_fragment: Preserve skb_iif during
    fragmentation (networking-stable-19_05_04).

  - ipv4: recompile ip options in ipv4_link_failure
    (networking-stable-19_04_19).

  - ipv4: set the tcp_min_rtt_wlen range from 0 to one day
    (networking-stable-19_04_30).

  - ipv6: fix cleanup ordering for ip6_mr failure
    (git-fixes).

  - ipv6: fix cleanup ordering for pingv6 registration
    (git-fixes).

  - ipv6/flowlabel: wait rcu grace period before put_pid()
    (git-fixes).

  - ipv6: invert flowlabel sharing check in process and user
    mode (git-fixes).

  - ipv6: mcast: fix unsolicited report interval after
    receiving querys (git-fixes).

  - ipvlan: Add the skb->mark as flow4's member to lookup
    route (bsc#1051510).

  - ipvlan: fix ipv6 outbound device (bsc#1051510).

  - ipvlan: use ETH_MAX_MTU as max mtu (bsc#1051510).

  - ipvs: call ip_vs_dst_notifier earlier than ipv6_dev_notf
    (git-fixes).

  - ipvs: fix buffer overflow with sync daemon and service
    (git-fixes).

  - ipvs: fix check on xmit to non-local addresses
    (git-fixes).

  - ipvs: fix race between ip_vs_conn_new() and
    ip_vs_del_dest() (bsc#1051510).

  - ipvs: fix rtnl_lock lockups caused by start_sync_thread
    (git-fixes).

  - ipvs: Fix signed integer overflow when setsockopt
    timeout (bsc#1051510).

  - ipvs: fix stats update from local clients (git-fixes).

  - iw_cxgb4: only allow 1 flush on user qps (bsc#1051510).

  - iwlwifi: mvm: check for length correctness in
    iwl_mvm_create_skb() (bsc#1051510).

  - iwlwifi: pcie: do not crash on invalid RX interrupt
    (bsc#1051510).

  - jbd2: check superblock mapped prior to committing
    (bsc#1136430).

  - kabi: drop LINUX_MIB_TCPWQUEUETOOBIG snmp counter
    (bsc#1137586).

  - kabi: implement map_lookup_elem_sys_only in another way
    (bsc#1083647).

  - kabi: move sysctl_tcp_min_snd_mss to preserve struct net
    layout (bsc#1137586).

  - kABI workaround for the new pci_dev.skip_bus_pm field
    addition (bsc#1051510).

  - kernel/signal.c: trace_signal_deliver when
    signal_group_exit (git-fixes).

  - kernel/sys.c: prctl: fix false positive in
    validate_prctl_map() (git-fixes).

  - keys: safe concurrent user->{session,uid}_keyring access
    (bsc#1135642).

  - kmsg: Update message catalog to latest IBM level
    (2019/03/08) (bsc#1128904 LTC#176078).

  - KVM: PPC: Book3S HV: Avoid lockdep debugging in TCE
    realmode handlers (bsc#1061840).

  - KVM: PPC: Book3S HV: XIVE: Do not clear IRQ data of
    passthrough interrupts (bsc#1061840).

  - KVM: PPC: Book3S: Protect memslots while validating user
    address (bsc#1061840).

  - KVM: PPC: Release all hardware TCE tables attached to a
    group (bsc#1061840).

  - KVM: PPC: Remove redundand permission bits removal
    (bsc#1061840).

  - KVM: PPC: Validate all tces before updating tables
    (bsc#1061840).

  - KVM: PPC: Validate TCEs against preregistered memory
    page sizes (bsc#1061840).

  - KVM: s390: fix memory overwrites when not using SCA
    entries (bsc#1136206).

  - KVM: s390: provide io interrupt kvm_stat (bsc#1136206).

  - KVM: s390: use created_vcpus in more places
    (bsc#1136206).

  - KVM: s390: vsie: fix < 8k check for the itdba
    (bsc#1136206).

  - l2tp: cleanup l2tp_tunnel_delete calls (bsc#1051510).

  - l2tp: filter out non-PPP sessions in
    pppol2tp_tunnel_ioctl() (git-fixes).

  - l2tp: fix missing refcount drop in
    pppol2tp_tunnel_ioctl() (git-fixes).

  - l2tp: only accept PPP sessions in pppol2tp_connect()
    (git-fixes).

  - l2tp: prevent pppol2tp_connect() from creating kernel
    sockets (git-fixes).

  - l2tp: revert 'l2tp: fix missing print session offset
    info' (bsc#1051510).

  - leds: avoid flush_work in atomic context (bsc#1051510).

  - leds: pwm: silently error out on EPROBE_DEFER
    (bsc#1051510).

  - livepatch: Convert error about unsupported reliable
    stacktrace into a warning (bsc#1071995).

  - livepatch: Remove custom kobject state handling
    (bsc#1071995).

  - livepatch: Remove duplicated code for early
    initialization (bsc#1071995).

  - mac80211/cfg80211: update bss channel on channel switch
    (bsc#1051510).

  - mac80211: Fix kernel panic due to use of txq after free
    (bsc#1051510).

  - mac80211: fix memory accounting with A-MSDU aggregation
    (bsc#1051510).

  - mac80211: fix unaligned access in mesh table hash
    function (bsc#1051510).

  - mac8390: Fix mmio access size probe (bsc#1051510).

  - MD: fix invalid stored role for a disk (bsc#1051510).

  - media: atmel: atmel-isc: fix INIT_WORK misplacement
    (bsc#1051510).

  - media: au0828: Fix NULL pointer dereference in
    au0828_analog_stream_enable() (bsc#1051510).

  - media: au0828: stop video streaming only when last user
    stops (bsc#1051510).

  - media: coda: clear error return value before picture run
    (bsc#1051510).

  - media: cpia2: Fix use-after-free in cpia2_exit
    (bsc#1051510).

  - media: davinci/vpbe: array underflow in
    vpbe_enum_outputs() (bsc#1051510).

  - media: go7007: avoid clang frame overflow warning with
    KASAN (bsc#1051510).

  - media: m88ds3103: serialize reset messages in
    m88ds3103_set_frontend (bsc#1051510).

  - media: omap_vout: potential buffer overflow in
    vidioc_dqbuf() (bsc#1051510).

  - media: ov2659: make S_FMT succeed even if requested
    format does not match (bsc#1051510).

  - media: saa7146: avoid high stack usage with clang
    (bsc#1051510).

  - media: smsusb: better handle optional alignment
    (bsc#1051510).

  - media: usb: siano: Fix false-positive 'uninitialized
    variable' warning (bsc#1051510).

  - media: usb: siano: Fix general protection fault in
    smsusb (bsc#1051510).

  - memcg: make it work on sparse non-0-node systems
    (bnc#1133616).

  - memcg: make it work on sparse non-0-node systems kabi
    (bnc#1133616).

  - mfd: da9063: Fix OTP control register names to match
    datasheets for DA9063/63L (bsc#1051510).

  - mfd: intel-lpss: Set the device in reset state when init
    (bsc#1051510).

  - mfd: max77620: Fix swapped FPS_PERIOD_MAX_US values
    (bsc#1051510).

  - mfd: tps65912-spi: Add missing of table registration
    (bsc#1051510).

  - mfd: twl6040: Fix device init errors for ACCCTL register
    (bsc#1051510).

  - mISDN: Check address length before reading address
    family (bsc#1051510).

  - mlxsw: spectrum: Fix autoneg status in ethtool
    (networking-stable-19_04_30).

  - mmc: block: Delete gendisk before cleaning up the
    request queue (bsc#1127616).

  - mmc: core: make pwrseq_emmc (partially) support sleepy
    GPIO controllers (bsc#1051510).

  - mmc: core: Verify SD bus width (bsc#1051510).

  - mmc: mmci: Prevent polling for busy detection in IRQ
    context (bsc#1051510).

  - mmc: sdhci-iproc: cygnus: Set NO_HISPD bit to fix HS50
    data hold time problem (bsc#1051510).

  - mmc: sdhci-iproc: Set NO_HISPD bit to fix HS50 data hold
    time problem (bsc#1051510).

  - mmc: sdhci-of-esdhc: add erratum A-009204 support
    (bsc#1051510).

  - mmc: sdhci-of-esdhc: add erratum eSDHC5 support
    (bsc#1051510).

  - mmc: sdhci-of-esdhc: add erratum eSDHC-A001 and A-008358
    support (bsc#1051510).

  - mmc_spi: add a status check for spi_sync_locked
    (bsc#1051510).

  - mm-Fix-modifying-of-page-protection-by-insert_pfn.patch:
    Fix buggy backport leading to MAP_SYNC failures
    (bsc#1137372)

  - mm/huge_memory: fix vmf_insert_pfn_{pmd, pud}() crash,
    handle unaligned addresses (bsc#1135330).

  - mm: thp: relax __GFP_THISNODE for MADV_HUGEPAGE mappings
    (bnc#1012382).

  - mount: copy the port field into the cloned nfs_server
    structure (bsc#1136990).

  - mwifiex: Fix heap overflow in
    mwifiex_uap_parse_tail_ies() (bsc#1136935).

  - mwifiex: Fix possible buffer overflows at parsing bss
    descriptor

  - neighbor: Call __ipv4_neigh_lookup_noref in neigh_xmit
    (git-fixes).

  - net: aquantia: fix rx checksum offload for UDP/TCP over
    IPv6 (networking-stable-19_03_28).

  - net: atm: Fix potential Spectre v1 vulnerabilities
    (networking-stable-19_04_19).

  - net: do not keep lonely packets forever in the gro hash
    (git-fixes).

  - net: dsa: bcm_sf2: fix buffer overflow doing set_rxnfc
    (networking-stable-19_05_04).

  - net: dsa: mv88e6xxx: fix handling of upper half of
    STATS_TYPE_PORT (git-fixes).

  - net: ena: fix return value of ena_com_config_llq_info()
    (bsc#1111696 bsc#1117561).

  - net: ethtool: not call vzalloc for zero sized memory
    request (networking-stable-19_04_10).

  - netfilter: bridge: Do not sabotage nf_hook calls from an
    l3mdev (git-fixes).

  - netfilter: ebtables: CONFIG_COMPAT: reject trailing data
    after last rule (git-fixes).

  - netfilter: ebtables: handle string from userspace with
    care (git-fixes).

  - netfilter: ebtables: reject non-bridge targets
    (git-fixes).

  - netfilter: ipset: do not call ipset_nest_end after
    nla_nest_cancel (git-fixes).

  - netfilter: nf_log: do not hold nf_log_mutex during user
    access (git-fixes).

  - netfilter: nf_log: fix uninit read in
    nf_log_proc_dostring (git-fixes).

  - netfilter: nf_tables: can't fail after linking rule into
    active rule list (git-fixes).

  - netfilter: nf_tables: check msg_type before
    nft_trans_set(trans) (git-fixes).

  - netfilter: nf_tables: fix leaking object reference count
    (git-fixes).

  - netfilter: nf_tables: fix NULL pointer dereference on
    nft_ct_helper_obj_dump() (git-fixes).

  - netfilter: nf_tables: release chain in flushing set
    (git-fixes).

  - netfilter: nft_compat: do not dump private area
    (git-fixes).

  - netfilter: x_tables: initialise match/target check
    parameter struct (git-fixes).

  - net: Fix a bug in removing queues from XPS map
    (git-fixes).

  - net: fix uninit-value in __hw_addr_add_ex() (git-fixes).

  - net: fou: do not use guehdr after iptunnel_pull_offloads
    in gue_udp_recv (networking-stable-19_04_19).

  - net-gro: Fix GRO flush when receiving a GSO packet
    (networking-stable-19_04_10).

  - net: hns3: remove resetting check in
    hclgevf_reset_task_schedule (bsc#1104353 bsc#1135056).

  - net/ibmvnic: Remove tests of member address
    (bsc#1137739).

  - net: initialize skb->peeked when cloning (git-fixes).

  - net/ipv4: defensive cipso option parsing (git-fixes).

  - net/ipv6: do not reinitialize ndev->cnf.addr_gen_mode on
    new inet6_dev (git-fixes).

  - net/ipv6: fix addrconf_sysctl_addr_gen_mode (git-fixes).

  - net/ipv6: propagate net.ipv6.conf.all.addr_gen_mode to
    devices (git-fixes).

  - net/ipv6: reserve room for IFLA_INET6_ADDR_GEN_MODE
    (git-fixes).

  - netlink: fix uninit-value in netlink_sendmsg
    (git-fixes).

  - net: make skb_partial_csum_set() more robust against
    overflows (git-fixes).

  - net/mlx5: Decrease default mr cache size
    (networking-stable-19_04_10).

  - net/mlx5e: Add a lock on tir list
    (networking-stable-19_04_10).

  - net/mlx5e: ethtool, Remove unsupported SFP EEPROM high
    pages query (networking-stable-19_04_30).

  - net/mlx5e: Fix error handling when refreshing TIRs
    (networking-stable-19_04_10).

  - net/mlx5e: Fix trailing semicolon (bsc#1075020).

  - net/mlx5e: IPoIB, Reset QP after channels are closed
    (bsc#1075020).

  - net: phy: marvell: Fix buffer overrun with stats
    counters (networking-stable-19_05_04).

  - net: rds: exchange of 8K and 1M pool
    (networking-stable-19_04_30).

  - net: rose: fix a possible stack overflow
    (networking-stable-19_03_28).

  - net/rose: fix unbound loop in rose_loopback_timer()
    (networking-stable-19_04_30).

  - net/sched: act_sample: fix divide by zero in the traffic
    path (networking-stable-19_04_10).

  - net/sched: do not dereference a->goto_chain to read the
    chain index (bsc#1064802 bsc#1066129).

  - net/sched: fix ->get helper of the matchall cls
    (networking-stable-19_04_10).

  - net: socket: fix potential spectre v1 gadget in
    socketcall (git-fixes).

  - net: stmmac: fix memory corruption with large MTUs
    (networking-stable-19_03_28).

  - net: stmmac: move stmmac_check_ether_addr() to driver
    probe (networking-stable-19_04_30).

  - net: test tailroom before appending to linear skb
    (git-fixes).

  - net: thunderx: do not allow jumbo frames with XDP
    (networking-stable-19_04_19).

  - net: thunderx: raise XDP MTU to 1508
    (networking-stable-19_04_19).

  - net: unbreak CONFIG_RETPOLINE=n builds (bsc#1124503).

  - net: use indirect call wrappers at GRO network layer
    (bsc#1124503).

  - net: use indirect call wrappers at GRO transport layer
    (bsc#1124503).

  - NFS add module option to limit NFSv4 minor version
    (jsc#PM-231).

  - nl80211: Add NL80211_FLAG_CLEAR_SKB flag for other NL
    commands (bsc#1051510).

  - nvme: Do not remove namespaces during reset
    (bsc#1131673).

  - nvme: flush scan_work when resetting controller
    (bsc#1131673).

  - nvmem: allow to select i.MX nvmem driver for i.MX 7D
    (bsc#1051510).

  - nvmem: core: fix read buffer in place (bsc#1051510).

  - nvmem: correct Broadcom OTP controller driver writes
    (bsc#1051510).

  - nvmem: Do not let a NULL cell_id for nvmem_cell_get()
    crash us (bsc#1051510).

  - nvmem: imx-ocotp: Add i.MX7D timing write clock setup
    support (bsc#1051510).

  - nvmem: imx-ocotp: Add support for banked OTP addressing
    (bsc#1051510).

  - nvmem: imx-ocotp: Enable i.MX7D OTP write support
    (bsc#1051510).

  - nvmem: imx-ocotp: Move i.MX6 write clock setup to
    dedicated function (bsc#1051510).

  - nvmem: imx-ocotp: Pass parameters via a struct
    (bsc#1051510).

  - nvmem: imx-ocotp: Restrict OTP write to IMX6 processors
    (bsc#1051510).

  - nvmem: imx-ocotp: Update module description
    (bsc#1051510).

  - nvmem: properly handle returned value nvmem_reg_read
    (bsc#1051510).

  - nvme-rdma: fix possible free of a non-allocated async
    event buffer (bsc#1120423).

  - nvme: skip nvme_update_disk_info() if the controller is
    not live (bsc#1128432).

  - objtool: Fix function fallthrough detection
    (bsc#1058115).

  - ocfs2: fix ocfs2 read inode data panic in ocfs2_iget
    (bsc#1136434).

  - of: fix clang -Wunsequenced for be32_to_cpu()
    (bsc#1135642).

  - p54: drop device reference count if fails to enable
    device (bsc#1135642).

  - packet: fix reserve calculation (git-fixes).

  - packet: in packet_snd start writing at link layer
    allocation (git-fixes).

  - packet: refine ring v3 block size test to hold one frame
    (git-fixes).

  - packet: reset network header if packet shorter than ll
    reserved space (git-fixes).

  - packets: Always register packet sk in the same order
    (networking-stable-19_03_28).

  - parport: Fix mem leak in parport_register_dev_model
    (bsc#1051510).

  - PCI: endpoint: Use EPC's device in
    dma_alloc_coherent()/dma_free_coherent() (git-fixes).

  - PCI: Factor out pcie_retrain_link() function
    (git-fixes).

  - PCI: Mark AMD Stoney Radeon R7 GPU ATS as broken
    (bsc#1051510).

  - PCI: Mark Atheros AR9462 to avoid bus reset
    (bsc#1051510).

  - PCI: PM: Avoid possible suspend-to-idle issue
    (bsc#1051510).

  - PCI: Work around Pericom PCIe-to-PCI bridge Retrain Link
    erratum (git-fixes).

  - perf tools: Add Hygon Dhyana support ().

  - platform/chrome: cros_ec_proto: check for NULL transfer
    function (bsc#1051510).

  - platform/x86: mlx-platform: Fix parent device in
    i2c-mux-reg device registration (bsc#1051510).

  - platform/x86: pmc_atom: Add Lex 3I380D industrial PC to
    critclk_systems DMI table (bsc#1051510).

  - platform/x86: pmc_atom: Add several Beckhoff Automation
    boards to critclk_systems DMI table (bsc#1051510).

  - PM / core: Propagate dev->power.wakeup_path when no
    callbacks (bsc#1051510).

  - powerpc: Always initialize input array when calling
    epapr_hypercall() (bsc#1065729).

  - powerpc/cacheinfo: add cacheinfo_teardown,
    cacheinfo_rebuild (bsc#1138374, LTC#178199).

  - powerpc/eeh: Fix race with driver un/bind (bsc#1065729).

  - powerpc: Fix HMIs on big-endian with
    CONFIG_RELOCATABLE=y (bsc#1065729).

  - powerpc/msi: Fix NULL pointer access in teardown code
    (bsc#1065729).

  - powerpc/perf: Fix MMCRA corruption by bhrb_filter
    (bsc#1053043).

  - powerpc/powernv/idle: Restore IAMR after idle
    (bsc#1065729).

  - powerpc/process: Fix sparse address space warnings
    (bsc#1065729).

  - powerpc/pseries: Fix oops in hotplug memory notifier
    (bsc#1138375, LTC#178204).

  - powerpc/pseries/mobility: prevent cpu hotplug during DT
    update (bsc#1138374, LTC#178199).

  - powerpc/pseries/mobility: rebuild cacheinfo hierarchy
    post-migration (bsc#1138374, LTC#178199).

  - power: supply: axp20x_usb_power: Fix typo in VBUS
    current limit macros (bsc#1051510).

  - power: supply: axp288_charger: Fix unchecked return
    value (bsc#1051510).

  - power: supply: max14656: fix potential use-before-alloc
    (bsc#1051510).

  - power: supply: sysfs: prevent endless uevent loop with
    CONFIG_POWER_SUPPLY_DEBUG (bsc#1051510).

  - ptrace: take into account saved_sigmask in
    PTRACE{GET,SET}SIGMASK (git-fixes).

  - qlcnic: Avoid potential NULL pointer dereference
    (bsc#1051510).

  - qmi_wwan: Add quirk for Quectel dynamic config
    (bsc#1051510).

  - RDMA/hns: Fix bug that caused srq creation to fail
    (bsc#1104427 ).

  - RDMA/rxe: Consider skb reserve space based on netdev of
    GID (bsc#1082387, bsc#1103992).

  - Revert 'ALSA: hda/realtek - Improve the headset mic for
    Acer Aspire laptops' (bsc#1051510).

  - Revert 'HID: wacom: generic: Send BTN_TOOL_PEN in prox
    once the pen enters range' (bsc#1051510).

  - rtc: 88pm860x: prevent use-after-free on device remove
    (bsc#1051510).

  - rtc: da9063: set uie_unsupported when relevant
    (bsc#1051510).

  - rtc: do not reference bogus function pointer in kdoc
    (bsc#1051510).

  - rtc: sh: Fix invalid alarm warning for non-enabled alarm
    (bsc#1051510).

  - rtlwifi: fix a potential NULL pointer dereference
    (bsc#1051510).

  - rxrpc: Fix error reception on AF_INET6 sockets
    (git-fixes).

  - rxrpc: Fix transport sockopts to get IPv4 errors on an
    IPv6 socket (git-fixes).

  - s390/qdio: clear intparm during shutdown (bsc#1134597
    LTC#177516).

  - scsi: qedf: fixup bit operations (bsc#1135542).

  - scsi: qedf: fixup locking in qedf_restart_rport()
    (bsc#1135542).

  - scsi: qedf: missing kref_put in qedf_xmit()
    (bsc#1135542).

  - scsi: qla2xxx: Declare local functions 'static'
    (bsc#1137444).

  - scsi: qla2xxx: fix error message on <qla2400
    (bsc#1118139).

  - scsi: qla2xxx: Fix function argument descriptions
    (bsc#1118139).

  - scsi: qla2xxx: Fix memory corruption during hba reset
    test (bsc#1118139).

  - scsi: qla2xxx: fix spelling mistake: 'existant' ->
    'existent' (bsc#1118139).

  - scsi: qla2xxx: fully convert to the generic DMA API
    (bsc#1137444).

  - scsi: qla2xxx: fx00 copypaste typo (bsc#1118139).

  - scsi: qla2xxx: Improve several kernel-doc headers
    (bsc#1137444).

  - scsi: qla2xxx: Introduce a switch/case statement in
    qlt_xmit_tm_rsp() (bsc#1137444).

  - scsi: qla2xxx: Make qla2x00_sysfs_write_nvram() easier
    to analyze (bsc#1137444).

  - scsi: qla2xxx: Make sure that qlafx00_ioctl_iosb_entry()
    initializes 'res' (bsc#1137444).

  - scsi: qla2xxx: NULL check before some freeing functions
    is not needed (bsc#1137444).

  - scsi: qla2xxx: Remove a set-but-not-used variable
    (bsc#1137444).

  - scsi: qla2xxx: remove the unused tcm_qla2xxx_cmd_wq
    (bsc#1118139).

  - scsi: qla2xxx: Remove two arguments from
    qlafx00_error_entry() (bsc#1137444).

  - scsi: qla2xxx: Remove unused symbols (bsc#1118139).

  - scsi: qla2xxx: Split the __qla2x00_abort_all_cmds()
    function (bsc#1137444).

  - scsi: qla2xxx: use lower_32_bits and upper_32_bits
    instead of reinventing them (bsc#1137444).

  - scsi: qla2xxx: Use %p for printing pointers
    (bsc#1118139).

  - sctp: avoid running the sctp state machine recursively
    (networking-stable-19_05_04).

  - sctp: fix identification of new acks for SFR-CACC
    (git-fixes).

  - sctp: get sctphdr by offset in sctp_compute_cksum
    (networking-stable-19_03_28).

  - sctp: initialize _pad of sockaddr_in before copying to
    user memory (networking-stable-19_04_10).

  - serial: sh-sci: disable DMA for uart_console
    (bsc#1051510).

  - signal: Always notice exiting tasks (git-fixes).

  - signal: Better detection of synchronous signals
    (git-fixes).

  - signal: Restore the stop PTRACE_EVENT_EXIT (git-fixes).

  - soc/fsl/qe: Fix an error code in qe_pin_request()
    (bsc#1051510).

  - spi: bitbang: Fix NULL pointer dereference in
    spi_unregister_master (bsc#1051510).

  - spi: Fix zero length xfer bug (bsc#1051510).

  - spi: Micrel eth switch: declare missing of table
    (bsc#1051510).

  - spi: pxa2xx: Add support for Intel Comet Lake
    (jsc#SLE-5331).

  - spi: pxa2xx: fix SCR (divisor) calculation
    (bsc#1051510).

  - spi: spi-fsl-spi: call spi_finalize_current_message() at
    the end (bsc#1051510).

  - spi : spi-topcliff-pch: Fix to handle empty DMA buffers
    (bsc#1051510).

  - spi: ST ST95HF NFC: declare missing of table
    (bsc#1051510).

  - spi: tegra114: reset controller on probe (bsc#1051510).

  - staging: vc04_services: Fix a couple error codes
    (bsc#1051510).

  - staging: vc04_services: prevent integer overflow in
    create_pagelist() (bsc#1051510).

  - staging: wlan-ng: fix adapter initialization failure
    (bsc#1051510).

  - stmmac: pci: Adjust IOT2000 matching
    (networking-stable-19_04_30).

  - switchtec: Fix unintended mask of MRPC event
    (git-fixes).

  - tcp: add tcp_min_snd_mss sysctl (bsc#1137586).

  - tcp: do not use ipv6 header for ipv4 flow
    (networking-stable-19_03_28).

  - tcp: enforce tcp_min_snd_mss in tcp_mtu_probing()
    (bsc#1137586).

  - tcp: Ensure DCTCP reacts to losses
    (networking-stable-19_04_10).

  - tcp: limit payload size of sacked skbs (bsc#1137586).

  - tcp: purge write queue in tcp_connect_init()
    (git-fixes).

  - tcp: tcp_fragment() should apply sane memory limits
    (bsc#1137586).

  - tcp: tcp_grow_window() needs to respect tcp_space()
    (networking-stable-19_04_19).

  - team: fix possible recursive locking when add slaves
    (networking-stable-19_04_30).

  - team: set slave to promisc if team is already in promisc
    mode (bsc#1051510).

  - test_firmware: Use correct snprintf() limit
    (bsc#1135642).

  - thermal: cpu_cooling: Actually trace CPU load in
    thermal_power_cpu_get_power (bsc#1051510).

  - thunderbolt: Fix to check for kmemdup failure
    (bsc#1051510).

  - thunderx: eliminate extra calls to put_page() for pages
    held for recycling (networking-stable-19_03_28).

  - thunderx: enable page recycling for non-XDP case
    (networking-stable-19_03_28).

  - tipc: fix hanging clients using poll with EPOLLOUT flag
    (git-fixes).

  - tipc: missing entries in name table of publications
    (networking-stable-19_04_19).

  - tools/cpupower: Add Hygon Dhyana support ().

  - tools lib traceevent: Fix missing equality check for
    strcmp (bsc#1129770).

  - tracing: Fix partial reading of trace event's id file
    (bsc#1136573).

  - treewide: Use DEVICE_ATTR_WO (bsc#1137739).

  - tty: ipwireless: fix missing checks for ioremap
    (bsc#1051510).

  - TTY: serial_core, add ->install (bnc#1129693).

  - tty: serial: msm_serial: Fix XON/XOFF (bsc#1051510).

  - tty/vt: fix write/write race in ioctl(KDSKBSENT) handler
    (bsc#1051510).

  - tun: add a missing rcu_read_unlock() in error path
    (networking-stable-19_03_28).

  - tun: properly test for IFF_UP
    (networking-stable-19_03_28).

  - udp: use indirect call wrappers for GRO socket lookup
    (bsc#1124503).

  - ufs: fix braino in ufs_get_inode_gid() for solaris UFS
    flavour (bsc#1135323).

  - Update config files: CONFIG_NVMEM_IMX_OCOTP=m for
    armvh7hl/lpae

  - Update config files. Debug kernel is not supported
    (bsc#1135492).

  - Update config files: disable CONFIG_IDE on ppc64le

  - Update config files for NFSv4.2 Enable NFSv4.2 support -
    jsc@PM-231 This requires a module parameter for NFSv4.2
    to actually be available on SLE12 and SLE15-SP0

  - Update cx2072x patches to follow the upstream
    development (bsc#1068546)

  - Update patch reference for ipmi_ssif fix (bsc#1135120)

  - usb: Add LPM quirk for Surface Dock GigE adapter
    (bsc#1051510).

  - usb: core: Add PM runtime calls to
    usb_hcd_platform_shutdown (bsc#1051510).

  - usb: core: Do not unbind interfaces following device
    reset failure (bsc#1051510).

  - usb: dwc2: Fix DMA cache alignment issues (bsc#1051510).

  - usb: Fix slab-out-of-bounds write in
    usb_get_bos_descriptor (bsc#1051510).

  - usbip: usbip_host: fix BUG: sleeping function called
    from invalid context (bsc#1051510).

  - usbip: usbip_host: fix stub_dev lock context imbalance
    regression (bsc#1051510).

  - usbnet: fix kernel crash after disconnect (bsc#1051510).

  - usb: rio500: fix memory leak in close after disconnect
    (bsc#1051510).

  - usb: rio500: refuse more than one device at a time
    (bsc#1051510).

  - usb: sisusbvga: fix oops in error path of sisusb_probe
    (bsc#1051510).

  - userfaultfd: use RCU to free the task struct when fork
    fails (git-fixes).

  - vhost: reject zero size iova range
    (networking-stable-19_04_19).

  - video: hgafb: fix potential NULL pointer dereference
    (bsc#1051510).

  - video: imsttfb: fix potential NULL pointer dereferences
    (bsc#1051510).

  - virtio_console: initialize vtermno value for ports
    (bsc#1051510).

  - vrf: check accept_source_route on the original netdevice
    (networking-stable-19_04_10).

  - vsock/virtio: Initialize core virtio vsock before
    registering the driver (bsc#1051510).

  - vt: always call notifier with the console lock held
    (bsc#1051510).

  - vxlan: Do not call gro_cells_destroy() before device is
    unregistered (networking-stable-19_03_28).

  - vxlan: trivial indenting fix (bsc#1051510).

  - vxlan: use __be32 type for the param vni in
    __vxlan_fdb_delete (bsc#1051510).

  - w1: fix the resume command API (bsc#1051510).

  - watchdog: imx2_wdt: Fix set_timeout for big timeout
    values (bsc#1051510).

  - x86_64: Add gap to int3 to allow for call emulation
    (bsc#1099658).

  - x86_64: Allow breakpoints to emulate call instructions
    (bsc#1099658).

  - x86/alternative: Init ideal_nops for Hygon Dhyana ().

  - x86/amd_nb: Check vendor in AMD-only functions ().

  - x86/apic: Add Hygon Dhyana support ().

  - x86/bugs: Add Hygon Dhyana to the respective mitigation
    machinery ().

  - x86/cpu: Create Hygon Dhyana architecture support file
    ().

  - x86/cpu: Get cache info and setup cache cpumap for Hygon
    Dhyana ().

  - x86/cpu/mtrr: Support TOP_MEM2 and get MTRR number ().

  - x86/events: Add Hygon Dhyana support to PMU
    infrastructure ().

  - x86/kvm: Add Hygon Dhyana support to KVM ().

  - x86/mce: Add Hygon Dhyana support to the MCA
    infrastructure ().

  - x86/mce: Do not disable MCA banks when offlining a CPU
    on AMD ().

  - x86/pci, x86/amd_nb: Add Hygon Dhyana support to PCI and
    northbridge ().

  - x86/smpboot: Do not use BSP INIT delay and MWAIT to idle
    on Dhyana ().

  - x86/speculation/mds: Fix documentation typo
    (bsc#1135642).

  - x86/xen: Add Hygon Dhyana support to Xen ().

  - xenbus: drop useless LIST_HEAD in xenbus_write_watch()
    and xenbus_file_write() (bsc#1065600).

  - xen/pciback: Do not disable PCI_COMMAND on PCI device
    reset (bsc#1065600).

  - xfrm6: avoid potential infinite loop in
    _decode_session6() (git-fixes).

  - xfrm6: call kfree_skb when skb is toobig (git-fixes).

  - xfrm: fix missing dst_release() after policy blocking
    lbcast and multicast (git-fixes).

  - xfrm: fix 'passing zero to ERR_PTR()' warning
    (git-fixes).

  - xfrm: reset crypto_done when iterating over multiple
    input xfrms (git-fixes).

  - xfrm: reset transport header back to network header
    after all input transforms ahave been applied
    (git-fixes).

  - xfrm_user: prevent leaking 2 bytes of kernel memory
    (git-fixes).

  - xfrm: Validate address prefix lengths in the xfrm
    selector (git-fixes).

  - xfs: add log item pinning error injection tag
    (bsc#1114427).

  - xfs: buffer lru reference count error injection tag
    (bsc#1114427).

  - xfs: check _btree_check_block value (bsc#1123663).

  - xfs: convert drop_writes to use the errortag mechanism
    (bsc#1114427).

  - xfs: create block pointer check functions (bsc#1123663).

  - xfs: create inode pointer verifiers (bsc#1114427).

  - xfs: do not clear imap_valid for a non-uptodate buffers
    (bsc#1138018).

  - xfs: do not look at buffer heads in xfs_add_to_ioend
    (bsc#1138013).

  - xfs: do not set the page uptodate in xfs_writepage_map
    (bsc#1138003).

  - xfs: do not use XFS_BMAPI_ENTRIRE in xfs_get_blocks
    (bsc#1137999).

  - xfs: do not use XFS_BMAPI_IGSTATE in xfs_map_blocks
    (bsc#1138005).

  - xfs: eof trim writeback mapping as soon as it is cached
    (bsc#1138019).

  - xfs: export _inobt_btrec_to_irec and
    _ialloc_cluster_alignment for scrub (bsc#1114427).

  - xfs: export various function for the online scrubber
    (bsc#1123663).

  - xfs: expose errortag knobs via sysfs (bsc#1114427).

  - xfs: fix s_maxbytes overflow problems (bsc#1137996).

  - xfs: fix unused variable warning in xfs_buf_set_ref()
    (bsc#1114427).

  - xfs: force summary counter recalc at next mount
    (bsc#1114427).

  - xfs: make errortag a per-mountpoint structure
    (bsc#1123663).

  - xfs: make xfs_writepage_map extent map centric
    (bsc#1138009).

  - xfs: minor cleanup for xfs_get_blocks (bsc#1138000).

  - xfs: move all writeback buffer_head manipulation into
    xfs_map_at_offset (bsc#1138014).

  - xfs: move error injection tags into their own file
    (bsc#1114427).

  - xfs: refactor btree block header checking functions
    (bsc#1123663).

  - xfs: refactor btree pointer checks (bsc#1123663).

  - xfs: refactor the tail of xfs_writepage_map
    (bsc#1138016).

  - xfs: refactor unmount record write (bsc#1114427).

  - xfs: remove the imap_valid flag (bsc#1138012).

  - xfs: remove unneeded parameter from XFS_TEST_ERROR
    (bsc#1123663).

  - xfs: remove unused parameter from xfs_writepage_map
    (bsc#1137995).

  - xfs: remove XFS_IO_INVALID (bsc#1138017).

  - xfs: remove xfs_map_cow (bsc#1138007).

  - xfs: remove xfs_reflink_find_cow_mapping (bsc#1138010).

  - xfs: remove xfs_reflink_trim_irec_to_next_cow
    (bsc#1138006).

  - xfs: remove xfs_start_page_writeback (bsc#1138015).

  - xfs: rename MAXPATHLEN to XFS_SYMLINK_MAXLEN
    (bsc#1123663).

  - xfs: rename the offset variable in xfs_writepage_map
    (bsc#1138008).

  - xfs: replace log_badcrc_factor knob with error injection
    tag (bsc#1114427).

  - xfs: sanity-check the unused space before trying to use
    it (bsc#1123663).

  - xfs: serialize unaligned dio writes against all other
    dio writes (bsc#1134936).

  - xfs: simplify xfs_map_blocks by using
    xfs_iext_lookup_extent directly (bsc#1138011).

  - xfs: skip CoW writes past EOF when writeback races with
    truncate (bsc#1137998).

  - xfs: xfs_reflink_convert_cow() memory allocation
    deadlock (bsc#1138002).

  - xhci: Convert xhci_handshake() to use
    readl_poll_timeout_atomic() (bsc#1051510).

  - xhci: Use %zu for printing size_t type (bsc#1051510).

  - xhci: update bounce buffer with correct sg num
    (bsc#1051510)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138375"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-debuginfo-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debuginfo-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debugsource-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-debuginfo-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-debuginfo-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debuginfo-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debugsource-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-debuginfo-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-devel-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-docs-html-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debugsource-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-macros-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-debugsource-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-qa-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-vanilla-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-syms-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debuginfo-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debugsource-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-4.12.14-lp150.12.64.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp150.12.64.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-base-debuginfo / etc");
}
