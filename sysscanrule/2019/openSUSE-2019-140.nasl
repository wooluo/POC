#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-140.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(121633);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/02 21:54:17");

  script_cve_id("CVE-2018-1120", "CVE-2018-16862", "CVE-2018-16884", "CVE-2018-19407", "CVE-2018-19824", "CVE-2018-19985", "CVE-2018-20169", "CVE-2018-9568", "CVE-2019-3459", "CVE-2019-3460");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-140)");
  script_summary(english:"Check for the openSUSE-2019-140 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 Linux kernel was updated to 4.4.172 to receive
various security and bugfixes.

The following security bugs were fixed :

  - CVE-2019-3459,CVE-2019-3460: Two remote information leak
    vulnerabilities in the Bluetooth stack were fixed that
    could potentially leak kernel information (bsc#1120758)

  - CVE-2018-19407: The vcpu_scan_ioapic function in
    arch/x86/kvm/x86.c allowed local users to cause a denial
    of service (NULL pointer dereference and BUG) via
    crafted system calls that reach a situation where ioapic
    is uninitialized (bnc#1116841).

  - CVE-2018-19985: The function hso_probe read if_num from
    the USB device (as an u8) and used it without a length
    check to index an array, resulting in an OOB memory read
    in hso_probe or hso _get_config_data that could be used
    by local attackers (bnc#1120743).

  - CVE-2018-1120: By mmap()ing a FUSE-backed file onto a
    process's memory containing command line arguments (or
    environment strings), an attacker can cause utilities
    from psutils or procps (such as ps, w) or any other
    program which made a read() call to the
    /proc/<pid>/cmdline (or /proc/<pid>/environ) files to
    block indefinitely (denial of service) or for some
    controlled time (as a synchronization primitive for
    other attacks) (bnc#1087082).

  - CVE-2018-16884: NFS41+ shares mounted in different
    network namespaces at the same time can make
    bc_svc_process() use wrong back-channel IDs and cause a
    use-after-free vulnerability. Thus a malicious container
    user can cause a host kernel memory corruption and a
    system panic. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out (bnc#1119946).

  - CVE-2018-20169: The USB subsystem mishandled size checks
    during the reading of an extra descriptor, related to
    __usb_get_extra_descriptor in drivers/usb/core/usb.c
    (bnc#1119714).

  - CVE-2018-9568: In sk_clone_lock of sock.c, there is a
    possible memory corruption due to type confusion. This
    could lead to local escalation of privilege with no
    additional execution privileges needed. User interaction
    is not needed for exploitation. (bnc#1118319).

  - CVE-2018-16862: A security flaw was found in a way that
    the cleancache subsystem clears an inode after the final
    file truncation (removal). The new file created with the
    same inode may contain leftover pages from cleancache
    and the old file data instead of the new one
    (bnc#1117186).

  - CVE-2018-19824: A local user could exploit a
    use-after-free in the ALSA driver by supplying a
    malicious USB Sound device (with zero interfaces) that
    is mishandled in usb_audio_probe in sound/usb/card.c
    (bnc#1118152).

The following non-security bugs were fixed :

  - 9p/net: put a lower bound on msize (bnc#1012382).

  - ACPI/IORT: Fix iort_get_platform_device_domain()
    uninitialized pointer value (bsc#1121239).

  - acpi/nfit: Block function zero DSMs (bsc#1123321).

  - acpi/nfit: Fix command-supported detection
    (bsc#1123323).

  - acpi/nfit, x86/mce: Handle only uncorrectable machine
    checks (bsc#1114648).

  - acpi/nfit, x86/mce: Validate a MCE's address before
    using it (bsc#1114648).

  - acpi/power: Skip duplicate power resource references in
    _PRx (bnc#1012382).

  - acpi/processor: Fix the return value of
    acpi_processor_ids_walk() (git fixes (acpi)).

  - aio: fix spectre gadget in lookup_ioctx (bnc#1012382).

  - aio: hold an extra file reference over AIO read/write
    operations (bsc#1116027).

  - alsa: ac97: Fix incorrect bit shift at AC97-SPSA control
    write (bnc#1012382).

  - alsa: bebob: fix model-id of unit for Apogee Ensemble
    (bnc#1012382).

  - alsa: control: Fix race between adding and removing a
    user element (bnc#1012382).

  - alsa: cs46xx: Potential NULL dereference in probe
    (bnc#1012382).

  - alsa: emu10k1: Fix potential Spectre v1 vulnerabilities
    (bnc#1012382).

  - alsa: emux: Fix potential Spectre v1 vulnerabilities
    (bnc#1012382).

  - alsa: hda: add mute LED support for HP EliteBook 840 G4
    (bnc#1012382).

  - alsa: hda: Add support for AMD Stoney Ridge
    (bnc#1012382).

  - alsa: hda/realtek - Disable headset Mic VREF for headset
    mode of ALC225 (bnc#1012382).

  - alsa: hda/tegra: clear pending irq handlers
    (bnc#1012382).

  - alsa: isa/wavefront: prevent some out of bound writes
    (bnc#1012382).

  - alsa: pcm: Call snd_pcm_unlink() conditionally at
    closing (bnc#1012382).

  - alsa: pcm: Fix interval evaluation with openmin/max
    (bnc#1012382).

  - alsa: pcm: Fix potential Spectre v1 vulnerability
    (bnc#1012382).

  - alsa: pcm: Fix starvation on down_write_nonblock()
    (bnc#1012382).

  - alsa: pcm: remove SNDRV_PCM_IOCTL1_INFO internal command
    (bnc#1012382).

  - alsa: rme9652: Fix potential Spectre v1 vulnerability
    (bnc#1012382).

  - alsa: sparc: Fix invalid snd_free_pages() at error path
    (bnc#1012382).

  - alsa: trident: Suppress gcc string warning
    (bnc#1012382).

  - alsa: usb-audio: Avoid access before bLength check in
    build_audio_procunit() (bnc#1012382).

  - alsa: usb-audio: Fix an out-of-bound read in
    create_composite_quirks (bnc#1012382).

  - alsa: wss: Fix invalid snd_free_pages() at error path
    (bnc#1012382).

  - arc: change defconfig defaults to ARCv2 (bnc#1012382).

  - arc: [devboards] Add support of NFSv3 ACL (bnc#1012382).

  - arc: io.h: Implement reads{x}()/writes{x}()
    (bnc#1012382).

  - arm64: Do not trap host pointer auth use to EL2
    (bnc#1012382).

  - arm64/kvm: consistently handle host HCR_EL2 flags
    (bnc#1012382).

  - arm64: perf: set suppress_bind_attrs flag to true
    (bnc#1012382).

  - arm64: remove no-op -p linker flag (bnc#1012382).

  - arm: 8814/1: mm: improve/fix ARM v7_dma_inv_range()
    unaligned address handling (bnc#1012382).

  - arm: imx: update the cpu power up timing setting on
    i.mx6sx (bnc#1012382).

  - arm: kvm: fix building with gcc-8 (bsc#1121241).

  - arm: OMAP1: ams-delta: Fix possible use of uninitialized
    field (bnc#1012382).

  - arm: OMAP2+: prm44xx: Fix section annotation on
    omap44xx_prm_enable_io_wakeup (bnc#1012382).

  - ASoC: dapm: Recalculate audio map forcely when card
    instantiated (bnc#1012382).

  - ASoC: omap-dmic: Add pm_qos handling to avoid overruns
    with CPU_IDLE (bnc#1012382).

  - ASoC: omap-mcpdm: Add pm_qos handling to avoid
    under/overruns with CPU_IDLE (bnc#1012382).

  - ata: Fix racy link clearance (bsc#1107866).

  - ath10k: fix kernel panic due to race in accessing arvif
    list (bnc#1012382).

  - ax25: fix a use-after-free in ax25_fillin_cb()
    (bnc#1012382).

  - b43: Fix error in cordic routine (bnc#1012382).

  - batman-adv: Expand merged fragment buffer for full
    packet (bnc#1012382).

  - bfs: add sanity check at bfs_fill_super() (bnc#1012382).

  - block/loop: Use global lock for ioctl() operation
    (bnc#1012382).

  - block/swim3: Fix -EBUSY error when re-opening device
    after unmount (Git-fixes).

  - bnx2x: Assign unique DMAE channel number for FW DMAE
    transactions (bnc#1012382).

  - bonding: fix 802.3ad state sent to partner when
    unbinding slave (bnc#1012382).

  - bpf: fix check of allowed specifiers in bpf_trace_printk
    (bnc#1012382).

  - bpf: support 8-byte metafield access (bnc#1012382).

  - bpf, trace: check event type in bpf_perf_event_read
    (bsc#1119970).

  - bpf, trace: use READ_ONCE for retrieving file ptr
    (bsc#1119967).

  - bpf/verifier: Add spi variable to check_stack_write()
    (bnc#1012382).

  - bpf/verifier: Pass instruction index to
    check_mem_access() and check_xadd() (bnc#1012382).

  - btrfs: Always try all copies when reading extent buffers
    (bnc#1012382).

  - btrfs: ensure path name is null terminated at
    btrfs_control_ioctl (bnc#1012382).

  - btrfs: Fix memory barriers usage with device stats
    counters (git-fixes).

  - btrfs: fix use-after-free when dumping free space
    (bnc#1012382).

  - btrfs: Handle error from btrfs_uuid_tree_rem call in
    _btrfs_ioctl_set_received_subvol (git-fixes).

  - btrfs: release metadata before running delayed refs
    (bnc#1012382).

  - btrfs: send, fix infinite loop due to directory rename
    dependencies (bnc#1012382).

  - btrfs: tree-checker: Check level for leaves and nodes
    (bnc#1012382).

  - btrfs: tree-checker: Do not check max block group size
    as current max chunk size limit is unreliable (fixes for
    bnc#1012382 bsc#1102875 bsc#1102877 bsc#1102879
    bsc#1102882 bsc#1102896).

  - btrfs: tree-checker: Fix misleading group system
    information (bnc#1012382).

  - btrfs: tree-check: reduce stack consumption in
    check_dir_item (bnc#1012382).

  - btrfs: validate type when reading a chunk (bnc#1012382).

  - btrfs: wait on ordered extents on abort cleanup
    (bnc#1012382).

  - can: dev: __can_get_echo_skb(): Do not crash the kernel
    if can_priv::echo_skb is accessed out of bounds
    (bnc#1012382).

  - can: dev: can_get_echo_skb(): factor out non sending
    code to __can_get_echo_skb() (bnc#1012382).

  - can: dev: __can_get_echo_skb(): print error message, if
    trying to echo non existing skb (bnc#1012382).

  - can: dev: __can_get_echo_skb(): replace struct can_frame
    by canfd_frame to access frame length (bnc#1012382).

  - can: gw: ensure DLC boundaries after CAN frame
    modification (bnc#1012382).

  - can: rcar_can: Fix erroneous registration (bnc#1012382).

  - cdc-acm: fix abnormal DATA RX issue for Mediatek
    Preloader (bnc#1012382).

  - ceph: do not update importing cap's mseq when handing
    cap export (bsc#1121275).

  - checkstack.pl: fix for aarch64 (bnc#1012382).

  - cifs: Do not hide EINTR after sending network packets
    (bnc#1012382).

  - cifs: Fix error mapping for SMB2_LOCK command which
    caused OFD lock problem (bnc#1012382).

  - cifs: Fix potential OOB access of lock element array
    (bnc#1012382).

  - cifs: Fix separator when building path from dentry
    (bnc#1012382).

  - cifs: In Kconfig CONFIG_CIFS_POSIX needs depends on
    legacy (insecure cifs) (bnc#1012382).

  - clk: imx6q: reset exclusive gates on init (bnc#1012382).

  - clk: mmp: Off by one in mmp_clk_add() (bnc#1012382).

  - cpufeature: avoid warning when compiling with clang
    (Git-fixes).

  - cpufreq: imx6q: add return value check for voltage scale
    (bnc#1012382).

  - crypto: authencesn - Avoid twice completion call in
    decrypt path (bnc#1012382).

  - crypto: authenc - fix parsing key with misaligned
    rta_len (bnc#1012382).

  - crypto: cts - fix crash on short inputs (bnc#1012382).

  - crypto: user - support incremental algorithm dumps
    (bsc#1120902).

  - crypto: x86/chacha20 - avoid sleeping with preemption
    disabled (bnc#1012382).

  - cw1200: Do not leak memory if krealloc failes
    (bnc#1012382).

  - debugobjects: avoid recursive calls with kmemleak
    (bnc#1012382).

  - Disable MSI also when pcie-octeon.pcie_disable on
    (bnc#1012382).

  - disable stringop truncation warnings for now
    (bnc#1012382).

  - dlm: fixed memory leaks after failed ls_remove_names
    allocation (bnc#1012382).

  - dlm: lost put_lkb on error path in receive_convert() and
    receive_unlock() (bnc#1012382).

  - dlm: memory leaks on error path in dlm_user_request()
    (bnc#1012382).

  - dlm: possible memory leak on error path in create_lkb()
    (bnc#1012382).

  - dmaengine: at_hdmac: fix memory leak in at_dma_xlate()
    (bnc#1012382).

  - dmaengine: at_hdmac: fix module unloading (bnc#1012382).

  - dm cache metadata: ignore hints array being too small
    during resize (Git-fixes).

  - dm crypt: add cryptographic data integrity protection
    (authenticated encryption) (Git-fixes).

  - dm crypt: factor IV constructor out to separate function
    (Git-fixes).

  - dm crypt: fix crash by adding missing check for auth key
    size (git-fixes).

  - dm crypt: fix error return code in crypt_ctr()
    (git-fixes).

  - dm crypt: fix memory leak in crypt_ctr_cipher_old()
    (git-fixes).

  - dm crypt: introduce new format of cipher with 'capi:'
    prefix (Git-fixes).

  - dm crypt: wipe kernel key copy after IV initialization
    (Git-fixes).

  - dm: do not allow readahead to limit IO size (git fixes
    (readahead)).

  - dm kcopyd: Fix bug causing workqueue stalls
    (bnc#1012382).

  - dm-multipath: do not assign cmd_flags in setup_clone()
    (bsc#1103156).

  - dm snapshot: Fix excessive memory usage and workqueue
    stalls (bnc#1012382).

  - dm thin: stop no_space_timeout worker when switching to
    write-mode (Git-fixes).

  - drivers: hv: vmbus: check the creation_status in
    vmbus_establish_gpadl() (bsc#1104098).

  - drivers: hv: vmbus: Return -EINVAL for the sys files for
    unopened channels (bnc#1012382).

  - drivers/sbus/char: add of_node_put() (bnc#1012382).

  - drivers/tty: add missing of_node_put() (bnc#1012382).

  - drm/ast: change resolution may cause screen blurred
    (bnc#1012382).

  - drm/ast: fixed cursor may disappear sometimes
    (bnc#1012382).

  - drm/ast: fixed reading monitor EDID not stable issue
    (bnc#1012382).

  - drm/ast: Fix incorrect free on ioregs (bsc#1106929)

  - drm/fb-helper: Ignore the value of
    fb_var_screeninfo.pixclock (bsc#1106929)

  - drm/ioctl: Fix Spectre v1 vulnerabilities (bnc#1012382).

  - drm/msm: Grab a vblank reference when waiting for
    commit_done (bnc#1012382).

  - drm: rcar-du: Fix external clock error checks
    (bsc#1106929)

  - drm: rcar-du: Fix vblank initialization (bsc#1106929)

  - e1000e: allow non-monotonic SYSTIM readings
    (bnc#1012382).

  - EDAC: Raise the maximum number of memory controllers
    (bsc#1120722).

  - efi/libstub/arm64: Use hidden attribute for struct
    screen_info reference (bsc#1122650).

  - exec: avoid gcc-8 warning for get_task_comm
    (bnc#1012382).

  - exportfs: do not read dentry after free (bnc#1012382).

  - ext2: fix potential use after free (bnc#1012382).

  - ext4: fix a potential fiemap/page fault deadlock w/
    inline_data (bnc#1012382).

  - ext4: Fix crash during online resizing (bsc#1122779).

  - ext4: fix EXT4_IOC_GROUP_ADD ioctl (bnc#1012382).

  - ext4: fix possible use after free in ext4_quota_enable
    (bnc#1012382).

  - ext4: force inode writes when nfsd calls
    commit_metadata() (bnc#1012382).

  - ext4: missing unlock/put_page() in
    ext4_try_to_write_inline_data() (bnc#1012382).

  - f2fs: Add sanity_check_inode() function (bnc#1012382).

  - f2fs: avoid unneeded loop in build_sit_entries
    (bnc#1012382).

  - f2fs: check blkaddr more accuratly before issue a bio
    (bnc#1012382).

  - f2fs: clean up argument of recover_data (bnc#1012382).

  - f2fs: clean up with is_valid_blkaddr() (bnc#1012382).

  - f2fs: detect wrong layout (bnc#1012382).

  - f2fs: enhance sanity_check_raw_super() to avoid
    potential overflow (bnc#1012382).

  - f2fs: factor out fsync inode entry operations
    (bnc#1012382).

  - f2fs: fix inode cache leak (bnc#1012382).

  - f2fs: fix invalid memory access (bnc#1012382).

  - f2fs: fix missing up_read (bnc#1012382).

  - f2fs: fix to avoid reading out encrypted data in page
    cache (bnc#1012382).

  - f2fs: fix to convert inline directory correctly
    (bnc#1012382).

  - f2fs: fix to determine start_cp_addr by sbi->cur_cp_pack
    (bnc#1012382).

  - f2fs: fix to do sanity check with block address in main
    area (bnc#1012382).

  - f2fs: fix to do sanity check with block address in main
    area v2 (bnc#1012382).

  - f2fs: fix to do sanity check with cp_pack_start_sum
    (bnc#1012382).

  - f2fs: fix to do sanity check with node footer and
    iblocks (bnc#1012382).

  - f2fs: fix to do sanity check with reserved blkaddr of
    inline inode (bnc#1012382).

  - f2fs: fix to do sanity check with secs_per_zone
    (bnc#1012382).

  - f2fs: fix to do sanity check with user_block_count
    (bnc#1012382).

  - f2fs: fix validation of the block count in
    sanity_check_raw_super (bnc#1012382).

  - f2fs: free meta pages if sanity check for ckpt is failed
    (bnc#1012382).

  - f2fs: give -EINVAL for norecovery and rw mount
    (bnc#1012382).

  - f2fs: introduce and spread verify_blkaddr (bnc#1012382).

  - f2fs: introduce get_checkpoint_version for cleanup
    (bnc#1012382).

  - f2fs: move sanity checking of cp into
    get_valid_checkpoint (bnc#1012382).

  - f2fs: not allow to write illegal blkaddr (bnc#1012382).

  - f2fs: put directory inodes before checkpoint in
    roll-forward recovery (bnc#1012382).

  - f2fs: remove an obsolete variable (bnc#1012382).

  - f2fs: return error during fill_super (bnc#1012382).

  - f2fs: sanity check on sit entry (bnc#1012382).

  - f2fs: use crc and cp version to determine roll-forward
    recovery (bnc#1012382).

  - fbdev: fbcon: Fix unregister crash when more than one
    framebuffer (bsc#1106929)

  - fbdev: fbmem: behave better with small rotated displays
    and many CPUs (bsc#1106929)

  - fix fragmentation series

  - Fix problem with sharetransport= and NFSv4
    (bsc#1114893).

  - floppy: fix race condition in __floppy_read_block_0()
    (Git-fixes).

  - fork: record start_time late (bnc#1012382).

  - fscache, cachefiles: remove redundant variable 'cache'
    (bnc#1012382).

  - fscache: Fix race in fscache_op_complete() due to split
    atomic_sub & read (Git-fixes).

  - fscache: Pass the correct cancelled indications to
    fscache_op_complete() (Git-fixes).

  - genwqe: Fix size check (bnc#1012382).

  - gfs2: Do not leave s_fs_info pointing to freed memory in
    init_sbd (bnc#1012382).

  - gfs2: Fix loop in gfs2_rbm_find (bnc#1012382).

  - git_sort.py: Remove non-existent remote tj/libata

  - gpiolib: Fix return value of gpio_to_desc() stub if
    !GPIOLIB (Git-fixes).

  - gpio: max7301: fix driver for use with CONFIG_VMAP_STACK
    (bnc#1012382).

  - gro_cell: add napi_disable in gro_cells_destroy
    (bnc#1012382).

  - hfs: do not free node before using (bnc#1012382).

  - hfsplus: do not free node before using (bnc#1012382).

  - hpwdt add dynamic debugging (bsc#1114417).

  - hpwdt calculate reload value on each use (bsc#1114417).

  - hugetlbfs: fix bug in pgoff overflow checking
    (bnc#1012382).

  - hwmon: (ina2xx) Fix current value calculation
    (bnc#1012382).

  - hwmon: (w83795) temp4_type has writable permission
    (bnc#1012382).

  - hwpoison, memory_hotplug: allow hwpoisoned pages to be
    offlined (bnc#1116336).

  - i2c: axxia: properly handle master timeout
    (bnc#1012382).

  - i2c: dev: prevent adapter retries and timeout being set
    as minus value (bnc#1012382).

  - i2c: scmi: Fix probe error on devices with an empty
    SMB0001 ACPI device node (bnc#1012382).

  - ib/hfi1: Fix an out-of-bounds access in get_hw_stats ().

  - ibmveth: Do not process frames after calling
    napi_reschedule (bcs#1123357).

  - ibmveth: fix DMA unmap error in ibmveth_xmit_start error
    path (bnc#1012382).

  - ibmvnic: Add ethtool private flag for driver-defined
    queue limits (bsc#1121726).

  - ibmvnic: Convert reset work item mutex to spin lock ().

  - ibmvnic: Fix non-atomic memory allocation in IRQ context
    ().

  - ibmvnic: Increase maximum queue size limit
    (bsc#1121726).

  - ibmvnic: Introduce driver limits for ring sizes
    (bsc#1121726).

  - ide: pmac: add of_node_put() (bnc#1012382).

  - ieee802154: lowpan_header_create check must check daddr
    (bnc#1012382).

  - input: elan_i2c - add ACPI ID for Lenovo IdeaPad
    330-15ARR (bnc#1012382).

  - input: elan_i2c - add ACPI ID for touchpad in ASUS
    Aspire F5-573G (bnc#1012382).

  - input: elan_i2c - add ELAN0620 to the ACPI table
    (bnc#1012382).

  - input: elan_i2c - add support for ELAN0621 touchpad
    (bnc#1012382).

  - input: matrix_keypad - check for errors from
    of_get_named_gpio() (bnc#1012382).

  - input: omap-keypad - fix idle configuration to not block
    SoC idle states (bnc#1012382).

  - input: omap-keypad - fix keyboard debounce configuration
    (bnc#1012382).

  - input: restore EV_ABS ABS_RESERVED (bnc#1012382).

  - input: xpad - add GPD Win 2 Controller USB IDs
    (bnc#1012382).

  - input: xpad - add Mad Catz FightStick TE 2 VID/PID
    (bnc#1012382).

  - input: xpad - add more third-party controllers
    (bnc#1012382).

  - input: xpad - add PDP device id 0x02a4 (bnc#1012382).

  - input: xpad - add product ID for Xbox One S pad
    (bnc#1012382).

  - input: xpad - add support for PDP Xbox One controllers
    (bnc#1012382).

  - input: xpad - add support for Xbox1 PDP Camo series
    gamepad (bnc#1012382).

  - input: xpad - add USB IDs for Mad Catz Brawlstick and
    Razer Sabertooth (bnc#1012382).

  - input: xpad - avoid using __set_bit() for capabilities
    (bnc#1012382).

  - input: xpad - constify usb_device_id (bnc#1012382).

  - input: xpad - correctly sort vendor id's (bnc#1012382).

  - input: xpad - correct xbox one pad device name
    (bnc#1012382).

  - input: xpad - do not depend on endpoint order
    (bnc#1012382).

  - input: xpad - fix GPD Win 2 controller name
    (bnc#1012382).

  - input: xpad - fix PowerA init quirk for some gamepad
    models (bnc#1012382).

  - input: xpad - fix rumble on Xbox One controllers with
    2015 firmware (bnc#1012382).

  - input: xpad - fix some coding style issues
    (bnc#1012382).

  - input: xpad - fix stuck mode button on Xbox One S pad
    (bnc#1012382).

  - input: xpad - fix Xbox One rumble stopping after 2.5
    secs (bnc#1012382).

  - input: xpad - handle 'present' and 'gone' correctly
    (bnc#1012382).

  - input: xpad - move reporting xbox one home button to
    common function (bnc#1012382).

  - input: xpad - power off wireless 360 controllers on
    suspend (bnc#1012382).

  - input: xpad - prevent spurious input from wired Xbox 360
    controllers (bnc#1012382).

  - input: xpad - quirk all PDP Xbox One gamepads
    (bnc#1012382).

  - input: xpad - remove spurious events of wireless xpad
    360 controller (bnc#1012382).

  - input: xpad - remove unused function (bnc#1012382).

  - input: xpad - restore LED state after device resume
    (bnc#1012382).

  - input: xpad - simplify error condition in init_output
    (bnc#1012382).

  - input: xpad - sort supported devices by USB ID
    (bnc#1012382).

  - input: xpad - support some quirky Xbox One pads
    (bnc#1012382).

  - input: xpad - sync supported devices with 360Controller
    (bnc#1012382).

  - input: xpad - sync supported devices with XBCD
    (bnc#1012382).

  - input: xpad - sync supported devices with xboxdrv
    (bnc#1012382).

  - input: xpad - update Xbox One Force Feedback Support
    (bnc#1012382).

  - input: xpad - use LED API when identifying wireless
    controllers (bnc#1012382).

  - input: xpad - validate USB endpoint type during probe
    (bnc#1012382).

  - input: xpad - workaround dead irq_out after suspend/
    resume (bnc#1012382).

  - input: xpad - xbox one elite controller support
    (bnc#1012382).

  - intel_th: msu: Fix an off-by-one in attribute store
    (bnc#1012382).

  - iommu/amd: Call free_iova_fast with pfn in map_sg
    (bsc#1106105).

  - iommu/amd: Fix amd_iommu=force_isolation (bsc#1106105).

  - iommu/amd: Fix IOMMU page flush when detach device from
    a domain (bsc#1106105).

  - iommu/amd: Unmap all mapped pages in error path of
    map_sg (bsc#1106105).

  - iommu/vt-d: Fix memory leak in
    intel_iommu_put_resv_regions() (bsc#1106105).

  - iommu/vt-d: Handle domain agaw being less than iommu
    agaw (bsc#1106105).

  - ip6mr: Fix potential Spectre v1 vulnerability
    (bnc#1012382).

  - ipmi:ssif: Fix handling of multi-part return messages
    (bnc#1012382).

  - ip: on queued skb use skb_header_pointer instead of
    pskb_may_pull (bnc#1012382).

  - ip_tunnel: Fix name string concatenate in
    __ip_tunnel_create() (bnc#1012382).

  - ipv4: Fix potential Spectre v1 vulnerability
    (bnc#1012382).

  - ipv4: ipv6: netfilter: Adjust the frag mem limit when
    truesize changes (bsc#1110286).

  - ipv6: Check available headroom in ip6_xmit() even
    without options (bnc#1012382).

  - ipv6: Consider sk_bound_dev_if when binding a socket to
    a v4 mapped address (bnc#1012382).

  - ipv6: explicitly initialize udp6_addr in
    udp_sock_create6() (bnc#1012382).

  - ipv6: fix kernel-infoleak in ipv6_local_error()
    (bnc#1012382).

  - ipv6: Take rcu_read_lock in __inet6_bind for mapped
    addresses (bnc#1012382).

  - isdn: fix kernel-infoleak in capi_unlocked_ioctl
    (bnc#1012382).

  - iser: set sector for ambiguous mr status errors
    (bnc#1012382).

  - iwlwifi: mvm: fix regulatory domain update when the
    firmware starts (bnc#1012382).

  - iwlwifi: mvm: support sta_statistics() even on older
    firmware (bnc#1012382).

  - ixgbe: Add function for checking to see if we can reuse
    page (bsc#1100105).

  - ixgbe: Add support for build_skb (bsc#1100105).

  - ixgbe: Add support for padding packet (bsc#1100105).

  - ixgbe: Break out Rx buffer page management
    (bsc#1100105).

  - ixgbe: Fix output from ixgbe_dump (bsc#1100105).

  - ixgbe: fix possible race in reset subtask (bsc#1101557).

  - ixgbe: Make use of order 1 pages and 3K buffers
    independent of FCoE (bsc#1100105).

  - ixgbe: Only DMA sync frame length (bsc#1100105).

  - ixgbe: recognize 1000BaseLX SFP modules as 1Gbps
    (bnc#1012382).

  - ixgbe: Refactor queue disable logic to take completion
    time into account (bsc#1101557).

  - ixgbe: Reorder Tx/Rx shutdown to reduce time needed to
    stop device (bsc#1101557).

  - ixgbe: Update code to better handle incrementing page
    count (bsc#1100105).

  - ixgbe: Update driver to make use of DMA attributes in Rx
    path (bsc#1100105).

  - ixgbe: Use length to determine if descriptor is done
    (bsc#1100105).

  - jffs2: Fix use of uninitialized delayed_work, lockdep
    breakage (bnc#1012382).

  - kabi: hwpoison, memory_hotplug: allow hwpoisoned pages
    to be offlined (bnc#1116336).

  - kabi: reorder new slabinfo fields in struct
    kmem_cache_node (bnc#1116653).

  - kbuild: suppress packed-not-aligned warning for default
    setting only (bnc#1012382).

  - kconfig: fix file name and line number of
    warn_ignored_character() (bnc#1012382).

  - kconfig: fix memory leak when EOF is encountered in
    quotation (bnc#1012382).

  - kdb: use memmove instead of overlapping memcpy
    (bnc#1012382).

  - kdb: Use strscpy with destination buffer size
    (bnc#1012382).

  - kernfs: Replace strncpy with memcpy (bnc#1012382).

  - kgdboc: fix KASAN global-out-of-bounds bug in
    param_set_kgdboc_var() (bnc#1012382).

  - kgdboc: Fix restrict error (bnc#1012382).

  - kgdboc: Fix warning with module build (bnc#1012382).

  - kobject: Replace strncpy with memcpy (bnc#1012382).

  - kvm/arm64: Fix caching of host MDCR_EL2 value
    (bsc#1121242).

  - kvm/arm: Restore banked registers and physical timer
    access on hyp_panic() (bsc#1121240).

  - kvm/mmu: Fix race in emulated page table writes
    (bnc#1012382).

  - kvm/nVMX: Eliminate vmcs02 pool (bnc#1012382).

  - kvm/nVMX: mark vmcs12 pages dirty on L2 exit
    (bnc#1012382).

  - kvm/PPC: Move and undef TRACE_INCLUDE_PATH/FILE
    (bnc#1012382).

  - kvm/svm: Allow direct access to MSR_IA32_SPEC_CTRL
    (bnc#1012382 bsc#1068032).

  - kvm/svm: Ensure an IBPB on all affected CPUs when
    freeing a vmcb (bsc#1114648).

  - kvm/VMX: Allow direct access to MSR_IA32_SPEC_CTRL
    (bnc#1012382 bsc#1068032 bsc#1096242 bsc#1096281).

  - kvm/VMX: Emulate MSR_IA32_ARCH_CAPABILITIES
    (bnc#1012382).

  - kvm/VMX: introduce alloc_loaded_vmcs (bnc#1012382).

  - kvm/VMX: make MSR bitmaps per-VCPU (bnc#1012382).

  - kvm/x86: Add IBPB support (bnc#1012382 bsc#1068032
    bsc#1068032).

  - kvm/x86: fix empty-body warnings (bnc#1012382).

  - kvm/x86: Remove indirect MSR op calls from SPEC_CTRL
    (bnc#1012382).

  - kvm/x86: Use jmp to invoke kvm_spurious_fault() from
    .fixup (bnc#1012382).

  - leds: call led_pwm_set() in leds-pwm to enforce default
    LED_OFF (bnc#1012382).

  - leds: leds-gpio: Fix return value check in
    create_gpio_led() (bnc#1012382).

  - leds: turn off the LED and wait for completion on
    unregistering LED class device (bnc#1012382).

  - libata: whitelist all SAMSUNG MZ7KM* solid-state disks
    (bnc#1012382).

  - libceph: fall back to sendmsg for slab pages
    (bsc#1118316).

  - libfc: sync strings with upstream versions
    (bsc#1114763).

  - lib/interval_tree_test.c: allow full tree search
    (bnc#1012382).

  - lib/interval_tree_test.c: allow users to limit scope of
    endpoint (bnc#1012382).

  - lib/interval_tree_test.c: make test options module
    parameters (bnc#1012382).

  - libnvdimm, {btt, blk}: do integrity setup before
    add_disk() (bsc#1118926).

  - libnvdimm, dimm: fix dpa reservation vs uninitialized
    label area (bsc#1118936).

  - libnvdimm: fix integer overflow static analysis warning
    (bsc#1118922).

  - libnvdimm: fix nvdimm_bus_lock() vs device_lock()
    ordering (bsc#1118915).

  - lib/rbtree_test.c: make input module parameters
    (bnc#1012382).

  - lib/rbtree-test: lower default params (bnc#1012382).

  - llc: do not use sk_eat_skb() (bnc#1012382).

  - loop: Fix double mutex_unlock(&loop_ctl_mutex) in
    loop_control_ioctl() (bnc#1012382).

  - loop: Fold __loop_release into loop_release
    (bnc#1012382).

  - loop: Get rid of loop_index_mutex (bnc#1012382).

  - LSM: Check for NULL cred-security on free (bnc#1012382).

  - mac80211: Clear beacon_int in ieee80211_do_stop
    (bnc#1012382).

  - mac80211: fix reordering of buffered broadcast packets
    (bnc#1012382).

  - mac80211_hwsim: fix module init error paths for netlink
    (bnc#1012382).

  - mac80211_hwsim: Timer should be initialized before
    device registered (bnc#1012382).

  - mac80211: ignore NullFunc frames in the duplicate
    detection (bnc#1012382).

  - mac80211: ignore tx status for PS stations in
    ieee80211_tx_status_ext (bnc#1012382).

  - matroxfb: fix size of memcpy (bnc#1012382).

  - md: batch flush requests (bsc#1119680).

  - md: do not check MD_SB_CHANGE_CLEAN in md_allow_write
    (Git-fixes).

  - media: dvb-frontends: fix i2c access helpers for KASAN
    (bnc#1012382).

  - media: em28xx: Fix misplaced reset of
    dev->v4l::field_count (bnc#1012382).

  - media: em28xx: Fix use-after-free when disconnecting
    (bnc#1012382).

  - media: firewire: Fix app_info parameter type in
    avc_ca{,_app}_info (bnc#1012382).

  - media: vb2: be sure to unlock mutex on errors
    (bnc#1012382).

  - media: vb2: vb2_mmap: move lock up (bnc#1012382).

  - media: vivid: fix error handling of kthread_run
    (bnc#1012382).

  - media: vivid: free bitmap_cap when updating
    std/timings/etc (bnc#1012382).

  - media: vivid: set min width/height to a value > 0
    (bnc#1012382).

  - mfd: tps6586x: Handle interrupts on suspend
    (bnc#1012382).

  - mips: Align kernel load address to 64KB (bnc#1012382).

  - mips: Ensure pmd_present() returns false after
    pmd_mknotpresent() (bnc#1012382).

  - mips: fix mips_get_syscall_arg o32 check (bnc#1012382).

  - mips: fix n32 compat_ipc_parse_version (bnc#1012382).

  - mips: ralink: Fix mt7620 nd_sd pinmux (bnc#1012382).

  - MIPS: SiByte: Enable swiotlb for SWARM, LittleSur and
    BigSur (bnc#1012382).

  - misc: mic/scif: fix copy-paste error in
    scif_create_remote_lookup (bnc#1012382).

  - mmc: atmel-mci: do not assume idle after
    atmci_request_end (bnc#1012382).

  - mmc: core: Reset HPI enabled state during re-init and in
    case of errors (bnc#1012382).

  - mm: cleancache: fix corruption on missed inode
    invalidation (bnc#1012382).

  - MMC: OMAP: fix broken MMC on OMAP15XX/OMAP5910/OMAP310
    (bnc#1012382).

  - mmc: omap_hsmmc: fix DMA API warning (bnc#1012382).

  - mm, devm_memremap_pages: kill mapping 'System RAM'
    support (bnc#1012382).

  - mm: do not miss the last page because of round-off error
    (bnc#1118798).

  - mm, hugetlb: fix huge_pte_alloc BUG_ON (bsc#1119204).

  - mm: hwpoison: call shake_page() after try_to_unmap() for
    mlocked page (bnc#1116336).

  - mm: lower the printk loglevel for __dump_page messages
    (generic hotplug debugability).

  - mm, memory_hotplug: be more verbose for memory offline
    failures (generic hotplug debugability).

  - mm, memory_hotplug: drop pointless block alignment
    checks from __offline_pages (generic hotplug
    debugability).

  - mm, memory_hotplug: print reason for the offlining
    failure (generic hotplug debugability).

  - mm: mlock: avoid increase mm->locked_vm on mlock() when
    already mlock2(,MLOCK_ONFAULT) (bnc#1012382).

  - mm/nommu.c: Switch __get_user_pages_unlocked() to use
    __get_user_pages() (bnc#1012382).

  - mm: only report isolation failures when offlining memory
    (generic hotplug debugability).

  - mm/page-writeback.c: do not break integrity writeback on
    ->writepage() error (bnc#1012382).

  - mm: Preserve _PAGE_DEVMAP across mprotect() calls
    (bsc#1118790).

  - mm: print more information about mapping in __dump_page
    (generic hotplug debugability).

  - mm, proc: be more verbose about unstable VMA flags in
    /proc/<pid>/smaps (bnc#1012382).

  - mm: put_and_wait_on_page_locked() while page is migrated
    (bnc#1109272).

  - mm: remove write/force parameters from
    __get_user_pages_locked() (bnc#1012382 bsc#1027260).

  - mm: remove write/force parameters from
    __get_user_pages_unlocked() (bnc#1012382 bsc#1027260).

  - mm: replace __access_remote_vm() write parameter with
    gup_flags (bnc#1012382).

  - mm: replace access_remote_vm() write parameter with
    gup_flags (bnc#1012382).

  - mm: replace get_user_pages_locked() write/force
    parameters with gup_flags (bnc#1012382 bsc#1027260).

  - mm: replace get_user_pages_unlocked() write/force
    parameters with gup_flags (bnc#1012382 bsc#1027260).

  - mm: replace get_user_pages() write/force parameters with
    gup_flags (bnc#1012382 bsc#1027260).

  - mm: replace get_vaddr_frames() write/force parameters
    with gup_flags (bnc#1012382).

  - mm, slab: faster active and free stats (bsc#116653, VM
    Performance).

  - mm/slab: improve performance of gathering slabinfo stats
    (bsc#116653, VM Performance).

  - mm, slab: maintain total slab count instead of active
    count (bsc#116653, VM Performance).

  - Move patches to sorted range, p1

  - mv88e6060: disable hardware level MAC learning
    (bnc#1012382).

  - mwifiex: Fix NULL pointer dereference in skb_dequeue()
    (bnc#1012382).

  - mwifiex: fix p2p device does not find in scan problem
    (bnc#1012382).

  - namei: allow restricted O_CREAT of FIFOs and regular
    files (bnc#1012382).

  - neighbour: Avoid writing before skb->head in
    neigh_hh_output() (bnc#1012382).

  - net: 8139cp: fix a BUG triggered by changing mtu with
    network traffic (bnc#1012382).

  - net: amd: add missing of_node_put() (bnc#1012382).

  - net: bcmgenet: fix OF child-node lookup (bnc#1012382).

  - net: bridge: fix a bug on using a neighbour cache entry
    without checking its state (bnc#1012382).

  - net: call sk_dst_reset when set SO_DONTROUTE
    (bnc#1012382).

  - net: ena: fix crash during ena_remove() (bsc#1108240).

  - net: ena: update driver version from 2.0.1 to 2.0.2
    (bsc#1108240).

  - net: faraday: ftmac100: remove netif_running(netdev)
    check before disabling interrupts (bnc#1012382).

  - netfilter: nf_tables: fix oops when inserting an element
    into a verdict map (bnc#1012382).

  - net: hisilicon: remove unexpected free_netdev
    (bnc#1012382).

  - net/ibmvnic: Fix RTNL deadlock during device reset
    (bnc#1115431).

  - net: ipv4: do not handle duplicate fragments as
    overlapping (bsc#1116345).

  - net/mlx4_core: Correctly set PFC param if global pause
    is turned off (bsc#1015336 bsc#1015337 bsc#1015340).

  - net/mlx4_core: Fix uninitialized variable compilation
    warning (bnc#1012382).

  - net/mlx4_core: Zero out lkey field in SW2HW_MPT fw
    command (bnc#1012382).

  - net/mlx4: Fix UBSAN warning of signed integer overflow
    (bnc#1012382).

  - net: phy: do not allow __set_phy_supported to add
    unsupported modes (bnc#1012382).

  - net: Prevent invalid access to skb->prev in
    __qdisc_drop_all (bnc#1012382).

  - netrom: fix locking in nr_find_socket() (bnc#1012382).

  - net: speed up skb_rbtree_purge() (bnc#1012382).

  - net: thunderx: fix NULL pointer dereference in
    nic_remove (bnc#1012382).

  - nfc: nfcmrvl_uart: fix OF child-node lookup
    (bnc#1012382).

  - nfit: skip region registration for incomplete control
    regions (bsc#1118930).

  - nfsv4: Do not exit the state manager without clearing
    NFS4CLNT_MANAGER_RUNNING (git-fixes).

  - nvme: validate controller state before rescheduling keep
    alive (bsc#1103257).

  - ocfs2: fix deadlock caused by ocfs2_defrag_extent()
    (bnc#1012382).

  - ocfs2: fix panic due to unrecovered local alloc
    (bnc#1012382).

  - ocfs2: fix potential use after free (bnc#1012382).

  - of: add helper to lookup compatible child node
    (bnc#1012382).

  - omap2fb: Fix stack memory disclosure (bsc#1106929)

  - packet: Do not leak dev refcounts on error exit
    (bnc#1012382).

  - packet: validate address length (bnc#1012382).

  - packet: validate address length if non-zero
    (bnc#1012382).

  - pci: altera: Check link status before retrain link
    (bnc#1012382).

  - pci: altera: Fix altera_pcie_link_is_up() (bnc#1012382).

  - pci: altera: Move retrain from fixup to
    altera_pcie_host_init() (bnc#1012382).

  - pci: altera: Poll for link training status after
    retraining the link (bnc#1012382).

  - pci: altera: Poll for link up status after retraining
    the link (bnc#1012382).

  - pci: altera: Reorder read/write functions (bnc#1012382).

  - pci: altera: Rework config accessors for use without a
    struct pci_bus (bnc#1012382).

  - perf/bpf: Convert perf_event_array to use struct file
    (bsc#1119967).

  - perf intel-pt: Fix error with config term 'pt=0'
    (bnc#1012382).

  - perf parse-events: Fix unchecked usage of strncpy()
    (bnc#1012382).

  - perf pmu: Suppress potential format-truncation warning
    (bnc#1012382).

  - perf svghelper: Fix unchecked usage of strncpy()
    (bnc#1012382).

  - pinctrl: sunxi: a83t: Fix IRQ offset typo for PH11
    (bnc#1012382).

  - platform/x86: asus-wmi: Tell the EC the OS will handle
    the display off hotkey (bnc#1012382).

  - powerpc/64s: consolidate MCE counter increment
    (bsc#1094244).

  - powerpc/boot: Fix random libfdt related build errors
    (bnc#1012382).

  - powerpc/boot: Request no dynamic linker for boot wrapper
    (bsc#1070805).

  - powerpc/cacheinfo: Report the correct shared_cpu_map on
    big-cores (bsc#1109695).

  - powerpc: Detect the presence of big-cores via 'ibm,
    thread-groups' (bsc#1109695).

  - powerpc: Fix COFF zImage booting on old powermacs
    (bnc#1012382).

  - powerpc, hotplug: Avoid to touch non-existent cpumasks
    (bsc#1109695).

  - powerpc: make use of for_each_node_by_type() instead of
    open-coding it (bsc#1109695).

  - powerpc/msi: Fix NULL pointer access in teardown code
    (bnc#1012382).

  - powerpc/numa: Suppress 'VPHN is not supported' messages
    (bnc#1012382).

  - powerpc/pseries/cpuidle: Fix preempt warning
    (bnc#1012382).

  - powerpc/setup: Add cpu_to_phys_id array (bsc#1109695).

  - powerpc/smp: Add cpu_l2_cache_map (bsc#1109695).

  - powerpc/smp: Add Power9 scheduler topology
    (bsc#1109695).

  - powerpc/smp: Rework CPU topology construction
    (bsc#1109695).

  - powerpc/smp: Use cpu_to_chip_id() to find core siblings
    (bsc#1109695).

  - powerpc/traps: restore recoverability of machine_check
    interrupts (bsc#1094244).

  - powerpc: Use cpu_smallcore_sibling_mask at SMT level on
    bigcores (bsc#1109695).

  - powerpc/xmon: Fix invocation inside lock region
    (bsc#1122885).

  - power: supply: olpc_battery: correct the temperature
    units (bnc#1012382).

  - proc: Remove empty line in /proc/self/status
    (bnc#1012382 bsc#1094823).

  - pstore: Convert console write to use ->write_buf
    (bnc#1012382).

  - pstore/ram: Do not treat empty buffers as valid
    (bnc#1012382).

  - qed: Fix bitmap_weight() check (bsc#1019695).

  - qed: Fix PTT leak in qed_drain() (bnc#1012382).

  - qed: Fix QM getters to always return a valid pq
    (bsc#1019695 ).

  - qed: Fix reading wrong value in loop condition
    (bnc#1012382).

  - r8169: Add support for new Realtek Ethernet
    (bnc#1012382).

  - rapidio/rionet: do not free skb before reading its
    length (bnc#1012382).

  - Refresh
    patches.kabi/x86-cpufeature-preserve-numbers.patch.
    (bsc#1122651)

  - Revert 'drm/rockchip: Allow driver to be shutdown on
    reboot/kexec' (bsc#1106929)

  - Revert 'exec: avoid gcc-8 warning for get_task_comm'
    (kabi).

  - Revert 'iommu/io-pgtable-arm: Check for v7s-incapable
    systems' (bsc#1106105).

  - Revert 'PCI/ASPM: Do not initialize link state when
    aspm_disabled is set' (bsc#1106105).

  - Revert 'usb: musb: musb_host: Enable HCD_BH flag to
    handle urb return in bottom half' (bsc#1047487).

  - Revert 'wlcore: Add missing PM call for
    wlcore_cmd_wait_for_event_or_timeout()' (bnc#1012382).

  - rocker: fix rocker_tlv_put_* functions for KASAN
    (bnc#1012382).

  - rtc: snvs: add a missing write sync (bnc#1012382).

  - rtc: snvs: Add timeouts to avoid kernel lockups
    (bnc#1012382).

  - rtnetlink: ndo_dflt_fdb_dump() only work for
    ARPHRD_ETHER devices (bnc#1012382).

  - s390/cpum_cf: Reject request for sampling in event
    initialization (bnc#1012382).

  - s390/mm: Check for valid vma before zapping in
    gmap_discard (bnc#1012382).

  - s390/qeth: fix length check in SNMP processing
    (bnc#1012382).

  - sbus: char: add of_node_put() (bnc#1012382).

  - scsi: bfa: convert to strlcpy/strlcat (bnc#1012382
    bsc#1019683, ).

  - scsi: bnx2fc: Fix NULL dereference in error handling
    (bnc#1012382).

  - scsi: Create two versions of
    scsi_internal_device_unblock() (bsc#1119877).

  - scsi: csiostor: Avoid content leaks and casts
    (bnc#1012382).

  - scsi: Introduce scsi_start_queue() (bsc#1119877).

  - scsi: libiscsi: Fix NULL pointer dereference in
    iscsi_eh_session_reset (bnc#1012382).

  - scsi: lpfc: Add Buffer overflow check, when nvme_info
    larger than PAGE_SIZE (bsc#1102660).

  - scsi: lpfc: devloss timeout race condition caused NULL
    pointer reference (bsc#1102660).

  - scsi: lpfc: Fix abort error path for NVMET
    (bsc#1102660).

  - scsi: lpfc: fix block guard enablement on SLI3 adapters
    (bsc#1079935).

  - scsi: lpfc: Fix driver crash when re-registering NVME
    rports (bsc#1102660).

  - scsi: lpfc: Fix ELS abort on SLI-3 adapters
    (bsc#1102660).

  - scsi: lpfc: Fix list corruption on the completion queue
    (bsc#1102660).

  - scsi: lpfc: Fix NVME Target crash in defer rcv logic
    (bsc#1102660).

  - scsi: lpfc: Fix panic if driver unloaded when port is
    offline (bsc#1102660).

  - scsi: lpfc: update driver version to 11.4.0.7-5
    (bsc#1102660).

  - scsi: Make __scsi_remove_device go straight from BLOCKED
    to DEL (bsc#1119877).

  - scsi: megaraid: fix out-of-bound array accesses
    (bnc#1012382).

  - scsi: Protect SCSI device state changes with a mutex
    (bsc#1119877).

  - scsi: qedi: Add ISCSI_BOOT_SYSFS to Kconfig
    (bsc#1043083).

  - scsi: Re-export scsi_internal_device_{,un}_block()
    (bsc#1119877).

  - scsi: sd: Fix cache_type_store() (bnc#1012382).

  - scsi: Split scsi_internal_device_block() (bsc#1119877).

  - scsi: target: add emulate_pr backstore attr to toggle PR
    support (bsc#1091405).

  - scsi: target: drop unused pi_prot_format attribute
    storage (bsc#1091405).

  - scsi: target: use consistent left-aligned ASCII INQUIRY
    data (bnc#1012382).

  - scsi: ufs: fix bugs related to NULL pointer access and
    array size (bnc#1012382).

  - scsi: ufs: fix race between clock gating and devfreq
    scaling work (bnc#1012382).

  - scsi: ufshcd: Fix race between clk scaling and ungate
    work (bnc#1012382).

  - scsi: ufshcd: release resources if probe fails
    (bnc#1012382).

  - scsi: use 'inquiry_mutex' instead of 'state_mutex'
    (bsc#1119877).

  - scsi: vmw_pscsi: Rearrange code to avoid multiple calls
    to free_irq during unload (bnc#1012382).

  - scsi: zfcp: fix posting too many status read buffers
    leading to adapter shutdown (bnc#1012382).

  - sctp: allocate sctp_sockaddr_entry with kzalloc
    (bnc#1012382).

  - sctp: clear the transport of some out_chunk_list chunks
    in sctp_assoc_rm_peer (bnc#1012382).

  - sctp: initialize sin6_flowinfo for ipv6 addrs in
    sctp_inet6addr_event (bnc#1012382).

  - selftests: Move networking/timestamping from
    Documentation (bnc#1012382).

  - selinux: fix GPF on invalid policy (bnc#1012382).

  - seq_file: fix incomplete reset on read from zero offset
    (Git-fixes).

  - series.conf: Move
    'patches.fixes/aio-hold-an-extra-file-reference-over-AIO
    -read-write.patch' into sorted section.

  - slab: alien caches must not be initialized if the
    allocation of the alien cache failed (bnc#1012382).

  - sock: Make sock->sk_stamp thread-safe (bnc#1012382).

  - spi: bcm2835: Avoid finishing transfer prematurely in
    IRQ mode (bnc#1012382).

  - spi: bcm2835: Fix book-keeping of DMA termination
    (bnc#1012382).

  - spi: bcm2835: Fix race on DMA termination (bnc#1012382).

  - spi: bcm2835: Unbreak the build of esoteric configs
    (bnc#1012382).

  - sr: pass down correctly sized SCSI sense buffer
    (bnc#1012382).

  - Staging: lustre: remove two build warnings
    (bnc#1012382).

  - staging: rts5208: fix gcc-8 logic error warning
    (bnc#1012382).

  - staging: speakup: Replace strncpy with memcpy
    (bnc#1012382).

  - sunrpc: Fix a bogus get/put in generic_key_to_expire()
    (bnc#1012382).

  - sunrpc: Fix a potential race in xprt_connect()
    (git-fixes).

  - sunrpc: fix cache_head leak due to queued request
    (bnc#1012382).

  - sunrpc: Fix leak of krb5p encode pages (bnc#1012382).

  - sunrpc: handle ENOMEM in rpcb_getport_async
    (bnc#1012382).

  - swiotlb: clean up reporting (bnc#1012382).

  - sysfs: Disable lockdep for driver bind/unbind files
    (bnc#1012382).

  - sysv: return 'err' instead of 0 in __sysv_write_inode
    (bnc#1012382).

  - target/iscsi: avoid NULL dereference in CHAP auth error
    path (bsc#1117165).

  - target: se_dev_attrib.emulate_pr ABI stability
    (bsc#1091405).

  - tcp: fix NULL ref in tail loss probe (bnc#1012382).

  - timer/debug: Change /proc/timer_list from 0444 to 0400
    (bnc#1012382).

  - tipc: fix uninit-value in tipc_nl_compat_bearer_enable
    (bnc#1012382).

  - tipc: fix uninit-value in tipc_nl_compat_doit
    (bnc#1012382).

  - tipc: fix uninit-value in
    tipc_nl_compat_link_reset_stats (bnc#1012382).

  - tipc: fix uninit-value in tipc_nl_compat_link_set
    (bnc#1012382).

  - tipc: fix uninit-value in tipc_nl_compat_name_table_dump
    (bnc#1012382).

  - tmpfs: make lseek(SEEK_DATA/SEK_HOLE) return ENXIO with
    a negative offset (bnc#1012382).

  - tpm: fix response size validation in tpm_get_random()
    (bsc#1020645, git-fixes).

  - tracing: Fix bad use of igrab in trace_uprobe.c
    (bsc#1120046).

  - tracing: Fix memory leak in set_trigger_filter()
    (bnc#1012382).

  - tracing: Fix memory leak of instance function hash
    filters (bnc#1012382).

  - tty/ldsem: Wake up readers after timed out down_write()
    (bnc#1012382).

  - tty: serial: 8250_mtk: always resume the device in probe
    (bnc#1012382).

  - tty: wipe buffer (bnc#1012382).

  - tty: wipe buffer if not echoing data (bnc#1012382).

  - tun: forbid iface creation with rtnl ops (bnc#1012382).

  - unifdef: use memcpy instead of strncpy (bnc#1012382).

  - Update config files: disable f2fs in the rest configs
    (boo#1109665)

  - uprobes: Fix handle_swbp() vs. unregister() + register()
    race once more (bnc#1012382).

  - usb: Add USB_QUIRK_DELAY_CTRL_MSG quirk for Corsair K70
    RGB (bnc#1012382).

  - usb: appledisplay: Add 27' Apple Cinema Display
    (bnc#1012382).

  - usb: cdc-acm: send ZLP for Telit 3G Intel based modems
    (bnc#1012382).

  - usb: check usb_get_extra_descriptor for proper size
    (bnc#1012382).

  - usb: core: Fix hub port connection events lost
    (bnc#1012382).

  - usb: core: quirks: add RESET_RESUME quirk for Cherry
    G230 Stream series (bnc#1012382).

  - usb: gadget: dummy: fix nonsensical comparisons
    (bnc#1012382).

  - usbnet: ipheth: fix potential recvmsg bug and recvmsg
    bug 2 (bnc#1012382).

  - usb: omap_udc: fix crashes on probe error and module
    removal (bnc#1012382).

  - usb: omap_udc: fix omap_udc_start() on 15xx machines
    (bnc#1012382).

  - usb: omap_udc: fix USB gadget functionality on Palm
    Tungsten E (bnc#1012382).

  - usb: omap_udc: use devm_request_irq() (bnc#1012382).

  - usb: quirk: add no-LPM quirk on SanDisk Ultra Flair
    device (bnc#1012382).

  - usb: r8a66597: Fix a possible concurrency use-after-free
    bug in r8a66597_endpoint_disable() (bnc#1012382).

  - usb: serial: option: add Fibocom NL668 series
    (bnc#1012382).

  - usb: serial: option: add Fibocom NL678 series
    (bnc#1012382).

  - usb: serial: option: add GosunCn ZTE WeLink ME3630
    (bnc#1012382).

  - usb: serial: option: add HP lt4132 (bnc#1012382).

  - usb: serial: option: add Simcom SIM7500/SIM7600 (MBIM
    mode) (bnc#1012382).

  - usb: serial: option: add Telit LN940 series
    (bnc#1012382).

  - usb: serial: pl2303: add ids for Hewlett-Packard HP POS
    pole displays (bnc#1012382).

  - usb: storage: add quirk for SMI SM3350 (bnc#1012382).

  - usb: storage: do not insert sane sense for SPC3+ when
    bad sense specified (bnc#1012382).

  - usb: usb-storage: Add new IDs to ums-realtek
    (bnc#1012382).

  - usb: xhci: fix timeout for transition from RExit to U0
    (bnc#1012382).

  - usb: xhci: fix uninitialized completion when USB3 port
    got wrong status (bnc#1012382).

  - usb: xhci: Prevent bus suspend if a port connect change
    or polling state is detected (bnc#1012382).

  - v9fs_dir_readdir: fix double-free on p9stat_read error
    (bnc#1012382).

  - vfs: Avoid softlockups in drop_pagecache_sb()
    (bsc#1118505).

  - vhost: make sure used idx is seen before log in
    vhost_add_used_n() (bnc#1012382).

  - virtio/s390: avoid race on vcdev->config (bnc#1012382).

  - virtio/s390: fix race in ccw_io_helper() (bnc#1012382).

  - VSOCK: Send reset control packet when socket is
    partially bound (bnc#1012382).

  - writeback: do not decrement wb->refcnt if !wb->bdi (git
    fixes (writeback)).

  - x86/earlyprintk/efi: Fix infinite loop on some screen
    widths (bnc#1012382).

  - x86/entry: spell EBX register correctly in documentation
    (bnc#1012382).

  - x86/MCE: Export memory_error() (bsc#1114648).

  - x86/MCE: Make correctable error detection look at the
    Deferred bit (bsc#1114648).

  - x86/mtrr: Do not copy uninitialized gentry fields back
    to userspace (bnc#1012382).

  - x86/speculation/l1tf: Drop the swap storage limit
    restriction when l1tf=off (bnc#1114871).

  - x86/speculation: Use synthetic bits for IBRS/IBPB/STIBP
    (bnc#1012382).

  - xen/balloon: Support xend-based toolstack (bnc#1065600).

  - xen/netback: dont overflow meta array (bnc#1099523).

  - xen/netfront: tolerate frags with no data (bnc#1012382).

  - xen/x86: add diagnostic printout to xen_mc_flush() in
    case of error (bnc#1116183).

  - xen: xlate_mmu: add missing header to fix 'W=1' warning
    (bnc#1012382).

  - xfrm: Fix bucket count reported to userspace
    (bnc#1012382).

  - xfs: Align compat attrlist_by_handle with native
    implementation (git-fixes).

  - xfs: fix quotacheck dquot id overflow infinite loop
    (bsc#1121621).

  - xhci: Add quirk to workaround the errata seen on Cavium
    Thunder-X2 Soc (bsc#1117162).

  - xhci: Do not prevent USB2 bus suspend in state check
    intended for USB3 only (bnc#1012382).

  - xhci: Prevent U1/U2 link pm states if exit latency is
    too long (bnc#1012382).

  - xprtrdma: Reset credit grant properly after a disconnect
    (git-fixes).

  - xtensa: enable coprocessors that are being flushed
    (bnc#1012382).

  - xtensa: fix coprocessor context offset definitions
    (bnc#1012382).

  - Yama: Check for pid death before checking ancestry
    (bnc#1012382).

  - x86/pkeys: Properly copy pkey state at fork()
    (bsc#1106105)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118930"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122650"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123357"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-pdf");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/07");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.172-86.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.172-86.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-devel / kernel-macros / kernel-source / etc");
}
