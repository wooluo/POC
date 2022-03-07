#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-274.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(122578);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/02 21:54:17");

  script_cve_id("CVE-2018-5391", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-7221", "CVE-2019-7222");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-274)");
  script_summary(english:"Check for the openSUSE-2019-274 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 kernel was updated to 4.4.175 to receive
various bugfixes.

The following security bugs were fixed :

  - CVE-2018-5391: Fixed a vulnerability, which allowed an
    attacker to cause a denial of service attack with low
    rates of packets targeting IP fragment re-assembly.
    (bsc#1103097)

  - CVE-2019-7221: Fixed a user-after-free vulnerability in
    the KVM hypervisor related to the emulation of a
    preemption timer, allowing an guest user/process to
    crash the host kernel. (bsc#1124732).

  - CVE-2019-7222: Fixed an information leakage in the KVM
    hypervisor related to handling page fault exceptions,
    which allowed a guest user/process to use this flaw to
    leak the host's stack memory contents to a guest
    (bsc#1124735).

The following non-security bugs were fixed :

  - ASoC: Intel: mrfld: fix uninitialized variable access
    (bnc#1012382).

  - ASoC: atom: fix a missing check of
    snd_pcm_lib_malloc_pages (bnc#1012382).

  - ASoC: fsl: Fix SND_SOC_EUKREA_TLV320 build error on
    i.MX8M (bnc#1012382).

  - Documentation/network: reword kernel version reference
    (bnc#1012382).

  - IB/core: type promotion bug in rdma_rw_init_one_mr() ().

  - IB/rxe: Fix incorrect cache cleanup in error flow ().

  - IB/rxe: replace kvfree with vfree ().

  - NFC: nxp-nci: Include unaligned.h instead of access_ok.h
    (bnc#1012382).

  - RDMA/bnxt_re: Fix a couple off by one bugs (bsc#1020413,
    ).

  - RDMA/bnxt_re: Synchronize destroy_qp with poll_cq
    (bsc#1125446).

  - Revert 'Input: elan_i2c - add ACPI ID for touchpad in
    ASUS Aspire F5-573G' (bnc#1012382).

  - Revert 'cifs: In Kconfig CONFIG_CIFS_POSIX needs depends
    on legacy (insecure cifs)' (bnc#1012382).

  - Revert 'exec: load_script: do not blindly truncate
    shebang string' (bnc#1012382).

  - Revert 'loop: Fix double mutex_unlock(&loop_ctl_mutex)
    in loop_control_ioctl()' (bnc#1012382).

  - Revert 'loop: Fold __loop_release into loop_release'
    (bnc#1012382).

  - Revert 'loop: Get rid of loop_index_mutex'
    (bnc#1012382).

  - Revert 'mmc: bcm2835: Fix DMA channel leak on probe
    error (bsc#1120902).'

  - Revert most of 4.4.174 (kabi).

  - acpi, nfit: Fix ARS overflow continuation (bsc#1125000).

  - acpi/nfit: fix cmd_rc for acpi_nfit_ctl to always return
    a value (bsc#1124775).

  - alpha: Fix Eiger NR_IRQS to 128 (bnc#1012382).

  - alpha: fix page fault handling for r16-r18 targets
    (bnc#1012382).

  - alsa: compress: Fix stop handling on compressed capture
    streams (bnc#1012382).

  - alsa: hda - Add quirk for HP EliteBook 840 G5
    (bnc#1012382).

  - alsa: hda - Serialize codec registrations (bnc#1012382).

  - alsa: usb-audio: Fix implicit fb endpoint setup by quirk
    (bnc#1012382).

  - arc: perf: map generic branches to correct hardware
    condition (bnc#1012382).

  - arm64: KVM: Skip MMIO insn after emulation
    (bnc#1012382).

  - arm64: ftrace: do not adjust the LR value (bnc#1012382).

  - arm64: hyp-stub: Forbid kprobing of the hyp-stub
    (bnc#1012382).

  - arm: 8808/1: kexec:offline panic_smp_self_stop CPU
    (bnc#1012382).

  - arm: OMAP2+: hwmod: Fix some section annotations
    (bnc#1012382).

  - arm: cns3xxx: Fix writing to wrong PCI config registers
    after alignment (bnc#1012382).

  - arm: dts: Fix OMAP4430 SDP Ethernet startup
    (bnc#1012382).

  - arm: dts: da850-evm: Correct the sound card name
    (bnc#1012382).

  - arm: dts: kirkwood: Fix polarity of GPIO fan lines
    (bnc#1012382).

  - arm: dts: mmp2: fix TWSI2 (bnc#1012382).

  - arm: iop32x/n2100: fix PCI IRQ mapping (bnc#1012382).

  - arm: pxa: avoid section mismatch warning (bnc#1012382).

  - batman-adv: Avoid WARN on net_device without parent in
    netns (bnc#1012382).

  - batman-adv: Force mac header to start of data on xmit
    (bnc#1012382).

  - bluetooth: Fix unnecessary error message for HCI request
    completion (bnc#1012382).

  - bnxt_re: Fix couple of memory leaks that could lead to
    IOMMU call traces (bsc#1020413).

  - can: bcm: check timer values before ktime conversion
    (bnc#1012382).

  - can: dev: __can_get_echo_skb(): fix bogous check for
    non-existing skb by removing it (bnc#1012382).

  - ceph: clear inode pointer when snap realm gets dropped
    by its inode (bsc#1125809).

  - char/mwave: fix potential Spectre v1 vulnerability
    (bnc#1012382).

  - cifs: Always resolve hostname before reconnecting
    (bnc#1012382).

  - cifs: Do not count -ENODATA as failure for query
    directory (bnc#1012382).

  - cifs: Fix possible hang during async MTU reads and
    writes (bnc#1012382).

  - cifs: Limit memory used by lock request calls to a page
    (bnc#1012382).

  - cifs: check ntwrk_buf_start for NULL before
    dereferencing it (bnc#1012382).

  - clk: imx6sl: ensure MMDC CH0 handshake is bypassed
    (bnc#1012382).

  - cpufreq: intel_pstate: Fix HWP on boot CPU after system
    resume (bsc#1120017).

  - cpuidle: big.LITTLE: fix refcount leak (bnc#1012382).

  - crypto: ux500 - Use proper enum in cryp_set_dma_transfer
    (bnc#1012382).

  - crypto: ux500 - Use proper enum in hash_set_dma_transfer
    (bnc#1012382).

  - cw1200: Fix concurrency use-after-free bugs in
    cw1200_hw_scan() (bnc#1012382).

  - dccp: fool proof ccid_hc_[rt]x_parse_options()
    (bnc#1012382).

  - debugfs: fix debugfs_rename parameter checking
    (bnc#1012382).

  - dlm: Do not swamp the CPU with callbacks queued during
    recovery (bnc#1012382).

  - dm thin: fix bug where bio that overwrites thin block
    ignores FUA (bnc#1012382).

  - dmaengine: imx-dma: fix wrong callback invoke
    (bnc#1012382).

  - drbd: Avoid Clang warning about pointless switch
    statment (bnc#1012382).

  - drbd: disconnect, if the wrong UUIDs are attached on a
    connected peer (bnc#1012382).

  - drbd: narrow rcu_read_lock in drbd_sync_handshake
    (bnc#1012382).

  - drbd: skip spurious timeout (ping-timeo) when failing
    promote (bnc#1012382).

  - drivers: core: Remove glue dirs from sysfs earlier
    (bnc#1012382).

  - drm/bufs: Fix Spectre v1 vulnerability (bnc#1012382).

  - drm/i915: Block fbdev HPD processing during suspend
    (bsc#1106929)

  - drm/i915: Prevent a race during I915_GEM_MMAP ioctl with
    WC set (bsc#1106929)

  - drm/modes: Prevent division by zero htotal
    (bnc#1012382).

  - drm/vmwgfx: Fix setting of dma masks (bsc#1106929)

  - drm/vmwgfx: Return error code from
    vmw_execbuf_copy_fence_user (bsc#1106929)

  - enic: fix checksum validation for IPv6 (bnc#1012382).

  - exec: load_script: do not blindly truncate shebang
    string (bnc#1012382).

  - f2fs: fix wrong return value of f2fs_acl_create
    (bnc#1012382).

  - f2fs: move dir data flush to write checkpoint process
    (bnc#1012382).

  - f2fs: read page index before freeing (bnc#1012382).

  - fs/dcache: Fix incorrect nr_dentry_unused accounting in
    shrink_dcache_sb() (bnc#1012382).

  - fs/epoll: drop ovflist branch prediction (bnc#1012382).

  - fs: add the fsnotify call to vfs_iter_write
    (bnc#1012382).

  - fs: do not scan the inode cache before SB_BORN is set
    (bnc#1012382).

  - fs: fix lost error code in dio_complete (bsc#1117744).

  - fuse: call pipe_buf_release() under pipe lock
    (bnc#1012382).

  - fuse: decrement NR_WRITEBACK_TEMP on the right page
    (bnc#1012382).

  - fuse: handle zero sized retrieve correctly
    (bnc#1012382).

  - futex: Fix (possible) missed wakeup (bsc#1050549).

  - gdrom: fix a memory leak bug (bnc#1012382).

  - gfs2: Revert 'Fix loop in gfs2_rbm_find' (bnc#1012382).

  - gpio: pl061: handle failed allocations (bnc#1012382).

  - gpu: ipu-v3: Fix CSI offsets for imx53 (bsc#1106929)

  - gpu: ipu-v3: Fix i.MX51 CSI control registers offset
    (bsc#1106929)

  - hid: debug: fix the ring buffer implementation
    (bnc#1012382).

  - hid: lenovo: Add checks to fix of_led_classdev_register
    (bnc#1012382).

  - hwmon: (lm80) Fix missing unlock on error in
    set_fan_div() (git-fixes).

  - hwmon: (lm80) fix a missing check of bus read in lm80
    probe (bnc#1012382).

  - hwmon: (lm80) fix a missing check of the status of SMBus
    read (bnc#1012382).

  - i2c-axxia: check for error conditions first
    (bnc#1012382).

  - igb: Fix an issue that PME is not enabled during runtime
    suspend (bnc#1012382).

  - inet: frags: add a pointer to struct netns_frags
    (bnc#1012382).

  - inet: frags: better deal with smp races (bnc#1012382).

  - inet: frags: break the 2GB limit for frags storage
    (bnc#1012382).

  - inet: frags: change inet_frags_init_net() return value
    (bnc#1012382).

  - inet: frags: do not clone skb in ip_expire()
    (bnc#1012382).

  - inet: frags: fix ip6frag_low_thresh boundary
    (bnc#1012382).

  - inet: frags: get rid of ipfrag_skb_cb/FRAG_CB
    (bnc#1012382).

  - inet: frags: get rif of inet_frag_evicting()
    (bnc#1012382).

  - inet: frags: refactor ipfrag_init() (bnc#1012382).

  - inet: frags: refactor ipv6_frag_init() (bnc#1012382).

  - inet: frags: refactor lowpan_net_frag_init()
    (bnc#1012382).

  - inet: frags: remove inet_frag_maybe_warn_overflow()
    (bnc#1012382).

  - inet: frags: remove some helpers (bnc#1012382).

  - inet: frags: reorganize struct netns_frags
    (bnc#1012382).

  - inet: frags: use rhashtables for reassembly units
    (bnc#1012382).

  - input: bma150 - register input device after setting
    private data (bnc#1012382).

  - input: elan_i2c - add ACPI ID for touchpad in Lenovo
    V330-15ISK (bnc#1012382).

  - input: elantech - enable 3rd button support on Fujitsu
    CELSIUS H780 (bnc#1012382).

  - input: xpad - add support for SteelSeries Stratus Duo
    (bnc#1012382).

  - intel_pstate: Update frequencies of policy->cpus only
    from ->set_policy() (bsc#1120017).

  - iommu/arm-smmu-v3: Use explicit mb() when moving cons
    pointer (bnc#1012382).

  - ip: add helpers to process in-order fragments faster
    (bnc#1012382).

  - ip: frags: fix crash in ip_do_fragment() (bnc#1012382).

  - ip: process in-order fragments efficiently
    (bnc#1012382).

  - ip: use rb trees for IP frag queue (bnc#1012382).

  - ipfrag: really prevent allocation on netns exit
    (bnc#1012382).

  - ipv4: frags: precedence bug in ip_expire()
    (bnc#1012382).

  - ipv6: Consider sk_bound_dev_if when binding a socket to
    an address (bnc#1012382).

  - ipv6: frags: rewrite ip6_expire_frag_queue()
    (bnc#1012382).

  - irqchip/gic-v3-its: Align PCI Multi-MSI allocation on
    their size (bnc#1012382).

  - isdn: hisax: hfc_pci: Fix a possible concurrency
    use-after-free bug in HFCPCI_l1hw() (bnc#1012382).

  - kABI: protect linux/kfifo.h include in hid-debug (kabi).

  - kABI: protect struct hda_bus (kabi).

  - kaweth: use skb_cow_head() to deal with cloned skbs
    (bnc#1012382).

  - kernel/exit.c: release ptraced tasks before
    zap_pid_ns_processes (bnc#1012382).

  - kernel/hung_task.c: break RCU locks based on jiffies
    (bnc#1012382).

  - kvm: VMX: Fix x2apic check in vmx_msr_bitmap_mode()
    (bsc#1124166).

  - kvm: VMX: Missing part of upstream commit 904e14fb7cb9
    (bsc#1124166).

  - kvm: x86: Fix single-step debugging (bnc#1012382).

  - kvm: x86: svm: report MSR_IA32_MCG_EXT_CTL as
    unsupported (bnc#1012382).

  - l2tp: copy 4 more bytes to linear part if necessary
    (bnc#1012382).

  - l2tp: fix reading optional fields of L2TPv3
    (bnc#1012382).

  - l2tp: remove l2specific_len dependency in l2tp_core
    (bnc#1012382).

  - libceph: avoid KEEPALIVE_PENDING races in
    ceph_con_keepalive() (bsc#1125810).

  - libnvdimm, pfn: Pad pfn namespaces relative to other
    regions (bsc#1124811).

  - libnvdimm: Use max contiguous area for namespace size
    (bsc#1124780).

  - libnvdimm: fix ars_status output length calculation
    (bsc#1124777).

  - locking/rwsem: Fix (possible) missed wakeup
    (bsc#1050549).

  - mac80211: ensure that mgmt tx skbs have tailroom for
    encryption (bnc#1012382).

  - mac80211: fix radiotap vendor presence bitmap handling
    (bnc#1012382).

  - media: DaVinci-VPBE: fix error handling in
    vpbe_initialize() (bnc#1012382).

  - memstick: Prevent memstick host from getting runtime
    suspended during card detection (bnc#1012382).

  - mips: OCTEON: do not set octeon_dma_bar_type if PCI is
    disabled (bnc#1012382).

  - mips: VDSO: Include $(ccflags-vdso) in o32,n32 .lds
    builds (bnc#1012382).

  - mips: bpf: fix encoding bug for mm_srlv32_op
    (bnc#1012382).

  - mips: cm: reprime error cause (bnc#1012382).

  - misc: vexpress: Off by one in vexpress_syscfg_exec()
    (bnc#1012382).

  - mm, oom: fix use-after-free in oom_kill_process
    (bnc#1012382).

  - mm, page_alloc: drop should_suppress_show_mem
    (bnc#1125892, bnc#1106061).

  - mm: migrate: do not rely on __PageMovable() of newpage
    after unlocking it (bnc#1012382).

  - mmc: bcm2835: Fix DMA channel leak on probe error
    (bsc#1120902).

  - mmc: sdhci-iproc: handle mmc_of_parse() errors during
    probe (bnc#1012382).

  - modpost: validate symbol names also in find_elf_symbol
    (bnc#1012382).

  - mtd: rawnand: gpmi: fix MX28 bus master lockup problem
    (bnc#1012382).

  - net/mlx4_core: Add masking for a few queries on HCA caps
    (bnc#1012382).

  - net/rose: fix NULL ax25_cb kernel panic (bnc#1012382).

  - net: Fix usage of pskb_trim_rcsum (bnc#1012382).

  - net: bridge: Fix ethernet header pointer before check
    skb forwardable (bnc#1012382).

  - net: dp83640: expire old TX-skb (bnc#1012382).

  - net: dsa: slave: Do not propagate flag changes on down
    slave interfaces (bnc#1012382).

  - net: fix pskb_trim_rcsum_slow() with odd trim offset
    (bnc#1012382).

  - net: ieee802154: 6lowpan: fix frag reassembly
    (bnc#1012382).

  - net: ipv4: Fix memory leak in network namespace
    dismantle (bnc#1012382).

  - net: ipv4: do not handle duplicate fragments as
    overlapping (bnc#1012382 bsc#1116345).

  - net: modify skb_rbtree_purge to return the truesize of
    all purged skbs (bnc#1012382).

  - net: pskb_trim_rcsum() and CHECKSUM_COMPLETE are friends
    (bnc#1012382).

  - net: systemport: Fix WoL with password after deep sleep
    (bnc#1012382).

  - net_sched: refetch skb protocol for each filter
    (bnc#1012382).

  - netrom: switch to sock timer API (bnc#1012382).

  - nfit: fix unchecked dereference in acpi_nfit_ctl
    (bsc#1125014).

  - nfs: nfs_compare_mount_options always compare auth
    flavors (bnc#1012382).

  - nfsd4: fix crash on writing v4_end_grace before nfsd
    startup (bnc#1012382).

  - niu: fix missing checks of niu_pci_eeprom_read
    (bnc#1012382).

  - ocfs2: do not clear bh uptodate for block read
    (bnc#1012382).

  - openvswitch: Avoid OOB read when parsing flow nlattrs
    (bnc#1012382).

  - perf tests evsel-tp-sched: Fix bitwise operator
    (bnc#1012382).

  - perf tools: Add Hygon Dhyana support (bnc#1012382).

  - perf unwind: Take pgoff into account when reporting elf
    to libdwfl (bnc#1012382).

  - perf unwind: Unwind with libdw does not take symfs into
    account (bnc#1012382).

  - perf/core: Do not WARN() for impossible ring-buffer
    sizes (bnc#1012382).

  - perf/core: Fix impossible ring-buffer sizes warning
    (bnc#1012382).

  - perf/x86/intel/uncore: Add Node ID mask (bnc#1012382).

  - pinctrl: msm: fix gpio-hog related boot issues
    (bnc#1012382).

  - platform/x86: asus-nb-wmi: Drop mapping of 0x33 and 0x34
    scan codes (bnc#1012382).

  - platform/x86: asus-nb-wmi: Map 0x35 to KEY_SCREENLOCK
    (bnc#1012382).

  - platform/x86: thinkpad_acpi: Proper model/release
    matching (bsc#1099810).

  - powerpc/pseries: add of_node_put() in
    dlpar_detach_node() (bnc#1012382).

  - powerpc/uaccess: fix warning/error with access_ok()
    (bnc#1012382).

  - ptp: check gettime64 return code in PTP_SYS_OFFSET ioctl
    (bnc#1012382).

  - rbd: do not return 0 on unmap if RBD_DEV_FLAG_REMOVING
    is set (bsc#1125808).

  - rcu: Force boolean subscript for expedited stall
    warnings (bnc#1012382).

  - rhashtable: Add rhashtable_lookup() (bnc#1012382).

  - rhashtable: add rhashtable_lookup_get_insert_key()
    (bnc#1012382 bsc#1042286).

  - rhashtable: add schedule points (bnc#1012382).

  - rhashtable: reorganize struct rhashtable layout
    (bnc#1012382).

  - s390/early: improve machine detection (bnc#1012382).

  - s390/smp: Fix calling smp_call_ipl_cpu() from ipl CPU
    (bnc#1012382).

  - s390/smp: fix CPU hotplug deadlock with CPU rescan
    (bnc#1012382).

  - sata_rcar: fix deferred probing (bnc#1012382).

  - sched/wake_q: Document wake_q_add() (bsc#1050549).

  - sched/wake_q: Fix wakeup ordering for wake_q
    (bsc#1050549).

  - sched/wake_q: Reduce reference counting for special
    users (bsc#1050549).

  - scripts/decode_stacktrace: only strip base path when a
    prefix of the path (bnc#1012382).

  - scripts/git_sort/git_sort.py: Add mkp/scsi
    5.0/scsi-fixes

  - scsi: lpfc: Correct LCB RJT handling (bnc#1012382).

  - scsi: lpfc: Correct MDS diag and nvmet configuration
    (bsc#1125796).

  - scsi: mpt3sas: API 's to support NVMe drive addition to
    SML (bsc#1117108).

  - scsi: mpt3sas: API's to remove nvme drive from sml
    (bsc#1117108).

  - scsi: mpt3sas: Add PCI device ID for Andromeda
    (bsc#1117108).

  - scsi: mpt3sas: Add an I/O barrier (bsc#1117108).

  - scsi: mpt3sas: Add ioc_<level> logging macros
    (bsc#1117108).

  - scsi: mpt3sas: Add nvme device support in slave alloc,
    target alloc and probe (bsc#1117108).

  - scsi: mpt3sas:
    Add-Task-management-debug-info-for-NVMe-drives
    (bsc#1117108).

  - scsi: mpt3sas: Added support for SAS Device Discovery
    Error Event (bsc#1117108).

  - scsi: mpt3sas: Added support for nvme encapsulated
    request message (bsc#1117108).

  - scsi: mpt3sas: Adding support for SAS3616 HBA device
    (bsc#1117108).

  - scsi: mpt3sas: Allow processing of events during driver
    unload (bsc#1117108).

  - scsi: mpt3sas: Annotate switch/case fall-through
    (bsc#1117108).

  - scsi: mpt3sas: As per MPI-spec, use combined reply queue
    for SAS3.5 controllers when HBA supports more than 16
    MSI-x vectors (bsc#1117108).

  - scsi: mpt3sas: Bug fix for big endian systems
    (bsc#1117108).

  - scsi: mpt3sas: Bump mpt3sas driver version to
    v16.100.00.00 (bsc#1117108).

  - scsi: mpt3sas: Cache enclosure pages during enclosure
    add (bsc#1117108).

  - scsi: mpt3sas: Configure reply post queue depth, DMA and
    sgl tablesize (bsc#1117108).

  - scsi: mpt3sas: Convert logging uses with MPT3SAS_FMT and
    reply_q_name to %s: (bsc#1117108).

  - scsi: mpt3sas: Convert logging uses with MPT3SAS_FMT
    without logging levels (bsc#1117108).

  - scsi: mpt3sas: Convert mlsleading uses of pr_<level>
    with MPT3SAS_FMT (bsc#1117108).

  - scsi: mpt3sas: Convert uses of pr_<level> with
    MPT3SAS_FMT to ioc_<level> (bsc#1117108).

  - scsi: mpt3sas: Display chassis slot information of the
    drive (bsc#1117108).

  - scsi: mpt3sas: Do not abort I/Os issued to NVMe drives
    while processing Async Broadcast primitive event
    (bsc#1117108).

  - scsi: mpt3sas: Do not access the structure after
    decrementing it's instance reference count
    (bsc#1117108).

  - scsi: mpt3sas: Do not use 32-bit atomic request
    descriptor for Ventura controllers (bsc#1117108).

  - scsi: mpt3sas: Enhanced handling of Sense Buffer
    (bsc#1117108).

  - scsi: mpt3sas: Fix a race condition in
    mpt3sas_base_hard_reset_handler() (bsc#1117108).

  - scsi: mpt3sas: Fix calltrace observed while running IO &
    reset (bsc#1117108).

  - scsi: mpt3sas: Fix indentation (bsc#1117108).

  - scsi: mpt3sas: Fix memory allocation failure test in
    'mpt3sas_base_attach()' (bsc#1117108).

  - scsi: mpt3sas: Fix nvme drives checking for tlr
    (bsc#1117108).

  - scsi: mpt3sas: Fix possibility of using invalid
    Enclosure Handle for SAS device after host reset
    (bsc#1117108).

  - scsi: mpt3sas: Fix removal and addition of vSES device
    during host reset (bsc#1117108).

  - scsi: mpt3sas: Fix sparse warnings (bsc#1117108).

  - scsi: mpt3sas: Fix, False timeout prints for ioctl and
    other internal commands during controller reset
    (bsc#1117108).

  - scsi: mpt3sas: Fixed memory leaks in driver
    (bsc#1117108).

  - scsi: mpt3sas: For NVME device, issue a protocol level
    reset (bsc#1117108).

  - scsi: mpt3sas: Handle NVMe PCIe device related events
    generated from firmware (bsc#1117108).

  - scsi: mpt3sas: Improve kernel-doc headers (bsc#1117108).

  - scsi: mpt3sas: Incorrect command status was set/marked
    as not used (bsc#1117108).

  - scsi: mpt3sas: Increase event log buffer to support 24
    port HBA's (bsc#1117108).

  - scsi: mpt3sas: Introduce API to get BAR0 mapped buffer
    address (bsc#1117108).

  - scsi: mpt3sas: Introduce Base function for cloning
    (bsc#1117108).

  - scsi: mpt3sas: Introduce function to clone mpi reply
    (bsc#1117108).

  - scsi: mpt3sas: Introduce function to clone mpi request
    (bsc#1117108).

  - scsi: mpt3sas: Introduce mpt3sas_get_st_from_smid()
    (bsc#1117108).

  - scsi: mpt3sas: Introduce struct mpt3sas_nvme_cmd
    (bsc#1117108).

  - scsi: mpt3sas: Lockless access for chain buffers
    (bsc#1117108).

  - scsi: mpt3sas: NVMe drive support for BTDHMAPPING ioctl
    command and log info (bsc#1117108).

  - scsi: mpt3sas: Optimize I/O memory consumption in driver
    (bsc#1117108).

  - scsi: mpt3sas: Pre-allocate RDPQ Array at driver boot
    time (bsc#1117108).

  - scsi: mpt3sas: Processing of Cable Exception events
    (bsc#1117108).

  - scsi: mpt3sas: Reduce memory footprint in kdump kernel
    (bsc#1117108).

  - scsi: mpt3sas: Remove KERN_WARNING from panic uses
    (bsc#1117108).

  - scsi: mpt3sas: Remove set-but-not-used variables
    (bsc#1117108).

  - scsi: mpt3sas: Remove unnecessary parentheses and
    simplify null checks (bsc#1117108).

  - scsi: mpt3sas: Remove unused macro MPT3SAS_FMT
    (bsc#1117108).

  - scsi: mpt3sas: Remove unused variable requeue_event
    (bsc#1117108).

  - scsi: mpt3sas: Replace PCI pool old API (bsc#1117108).

  - scsi: mpt3sas: Replace PCI pool old API (bsc#1117108).

  - scsi: mpt3sas: Report Firmware Package Version from HBA
    Driver (bsc#1117108).

  - scsi: mpt3sas: SGL to PRP Translation for I/Os to NVMe
    devices (bsc#1117108).

  - scsi: mpt3sas: Set NVMe device queue depth as 128
    (bsc#1117108).

  - scsi: mpt3sas: Split _base_reset_handler(),
    mpt3sas_scsih_reset_handler() and
    mpt3sas_ctl_reset_handler() (bsc#1117108).

  - scsi: mpt3sas: Swap I/O memory read value back to cpu
    endianness (bsc#1117108).

  - scsi: mpt3sas: Update MPI Headers (bsc#1117108).

  - scsi: mpt3sas: Update driver version '25.100.00.00'
    (bsc#1117108).

  - scsi: mpt3sas: Update driver version '26.100.00.00'
    (bsc#1117108).

  - scsi: mpt3sas: Update mpt3sas driver version
    (bsc#1117108).

  - scsi: mpt3sas: Updated MPI headers to v2.00.48
    (bsc#1117108).

  - scsi: mpt3sas: Use dma_pool_zalloc (bsc#1117108).

  - scsi: mpt3sas: always use first reserved smid for ioctl
    passthrough (bsc#1117108).

  - scsi: mpt3sas: check command status before attempting
    abort (bsc#1117108).

  - scsi: mpt3sas: clarify mmio pointer types (bsc#1117108).

  - scsi: mpt3sas: cleanup _scsih_pcie_enumeration_event()
    (bsc#1117108).

  - scsi: mpt3sas: fix an out of bound write (bsc#1117108).

  - scsi: mpt3sas: fix dma_addr_t casts (bsc#1117108).

  - scsi: mpt3sas: fix format overflow warning
    (bsc#1117108).

  - scsi: mpt3sas: fix oops in error handlers after
    shutdown/unload (bsc#1117108).

  - scsi: mpt3sas: fix possible memory leak (bsc#1117108).

  - scsi: mpt3sas: fix pr_info message continuation
    (bsc#1117108).

  - scsi: mpt3sas: fix spelling mistake: 'disbale' ->
    'disable' (bsc#1117108).

  - scsi: mpt3sas: lockless command submission
    (bsc#1117108).

  - scsi: mpt3sas: make function _get_st_from_smid static
    (bsc#1117108).

  - scsi: mpt3sas: open-code _scsih_scsi_lookup_get()
    (bsc#1117108).

  - scsi: mpt3sas: remove a stray KERN_INFO (bsc#1117108).

  - scsi: mpt3sas: remove redundant copy_from_user in
    _ctl_getiocinfo (bsc#1117108).

  - scsi: mpt3sas: remove redundant wmb (bsc#1117108).

  - scsi: mpt3sas: scan and add nvme device after controller
    reset (bsc#1117108).

  - scsi: mpt3sas: separate out _base_recovery_check()
    (bsc#1117108).

  - scsi: mpt3sas: set default value for cb_idx
    (bsc#1117108).

  - scsi: mpt3sas: simplify _wait_for_commands_to_complete()
    (bsc#1117108).

  - scsi: mpt3sas: simplify mpt3sas_scsi_issue_tm()
    (bsc#1117108).

  - scsi: mpt3sas: simplify task management functions
    (bsc#1117108).

  - scsi: mpt3sas: switch to generic DMA API (bsc#1117108).

  - scsi: mpt3sas: switch to pci_alloc_irq_vectors
    (bsc#1117108).

  - scsi: mpt3sas: use list_splice_init() (bsc#1117108).

  - scsi: mpt3sas: wait for and flush running commands on
    shutdown/unload (bsc#1117108).

  - scsi: qla2xxx: Fix deadlock between ATIO and HW lock
    (bsc#1125794).

  - scsi: target: make the pi_prot_format ConfigFS path
    readable (bsc#1123933).

  - sd: disable logical block provisioning if 'lbpme' is not
    set (bsc#1086095 bsc#1078355).

  - seq_buf: Make seq_buf_puts() null-terminate the buffer
    (bnc#1012382).

  - serial: fsl_lpuart: clear parity enable bit when disable
    parity (bnc#1012382).

  - signal: Always notice exiting tasks (bnc#1012382).

  - signal: Better detection of synchronous signals
    (bnc#1012382).

  - signal: Restore the stop PTRACE_EVENT_EXIT
    (bnc#1012382).

  - skge: potential memory corruption in skge_get_regs()
    (bnc#1012382).

  - smack: fix access permissions for keyring (bnc#1012382).

  - smsc95xx: Use skb_cow_head to deal with cloned skbs
    (bnc#1012382).

  - soc/tegra: Do not leak device tree node reference
    (bnc#1012382).

  - staging: iio: ad7780: update voltage on read
    (bnc#1012382).

  - staging: iio: adc: ad7280a: handle error from
    __ad7280_read32() (bnc#1012382).

  - staging: rtl8188eu: Add device code for D-Link DWA-121
    rev B1 (bnc#1012382).

  - staging:iio:ad2s90: Make probe handle spi_setup failure
    (bnc#1012382).

  - sunvdc: Do not spin in an infinite loop when
    vio_ldc_send() returns EAGAIN (bnc#1012382).

  - test_hexdump: use memcpy instead of strncpy
    (bnc#1012382).

  - thermal: hwmon: inline helpers when CONFIG_THERMAL_HWMON
    is not set (bnc#1012382).

  - timekeeping: Use proper seqcount initializer
    (bnc#1012382).

  - tipc: use destination length for copy string
    (bnc#1012382).

  - tracing/uprobes: Fix output for multiple string
    arguments (bnc#1012382).

  - tty/ldsem: Add lockdep asserts for ldisc_sem
    (bnc#1105428).

  - tty/ldsem: Convert to regular lockdep annotations
    (bnc#1105428).

  - tty/ldsem: Decrement wait_readers on timeouted
    down_read() (bnc#1105428).

  - tty/n_hdlc: fix __might_sleep warning (bnc#1012382).

  - tty: Do not block on IO when ldisc change is pending
    (bnc#1105428).

  - tty: Do not hold ldisc lock in tty_reopen() if ldisc
    present (bnc#1105428).

  - tty: Handle problem if line discipline does not have
    receive_buf (bnc#1012382).

  - tty: Hold tty_ldisc_lock() during tty_reopen()
    (bnc#1105428).

  - tty: Simplify tty->count math in tty_reopen()
    (bnc#1105428).

  - tty: fix data race between tty_init_dev and flush of buf
    (bnc#1105428).

  - tty: serial: samsung: Properly set flags in autoCTS mode
    (bnc#1012382).

  - uapi/if_ether.h: move __UAPI_DEF_ETHHDR libc define
    (bnc#1012382).

  - uapi/if_ether.h: prevent redefinition of struct ethhdr
    (bnc#1012382).

  - ucc_geth: Reset BQL queue when stopping device
    (bnc#1012382).

  - udf: Fix BUG on corrupted inode (bnc#1012382).

  - um: Avoid marking pages with 'changed protection'
    (bnc#1012382).

  - usb: dwc2: Remove unnecessary kfree (bnc#1012382).

  - usb: gadget: udc: net2272: Fix bitwise and boolean
    operations (bnc#1012382).

  - usb: hub: delay hub autosuspend if USB3 port is still
    link training (bnc#1012382).

  - usb: phy: am335x: fix race condition in _probe
    (bnc#1012382).

  - usb: serial: pl2303: add new PID to support PL2303TB
    (bnc#1012382).

  - usb: serial: simple: add Motorola Tetra TPG2200 device
    id (bnc#1012382).

  - video: clps711x-fb: release disp device node in probe()
    (bnc#1012382).

  - vt: invoke notifier on screen size change (bnc#1012382).

  - x86/MCE: Initialize mce.bank in the case of a fatal
    error in mce_no_way_out() (bnc#1012382).

  - x86/PCI: Fix Broadcom CNB20LE unintended sign extension
    (redux) (bnc#1012382).

  - x86/a.out: Clear the dump structure initially
    (bnc#1012382).

  - x86/fpu: Add might_fault() to user_insn() (bnc#1012382).

  - x86/kaslr: Fix incorrect i8254 outb() parameters
    (bnc#1012382).

  - x86/platform/UV: Use efi_runtime_lock to serialise BIOS
    calls (bnc#1012382).

  - x86/xen: dont add memory above max allowed allocation
    (bsc#1117645).

  - x86: respect memory size limiting via mem= parameter
    (bsc#1117645).

  - xfrm6_tunnel: Fix spi check in __xfrm6_tunnel_alloc_spi
    (bnc#1012382).

  - xfrm: refine validation of template and selector
    families (bnc#1012382)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117744"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120017"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=802154"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/04");
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

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.175-89.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.175-89.1") ) flag++;

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
