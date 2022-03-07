#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1407.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(125303);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/21  9:43:49");

  script_cve_id("CVE-2018-1000204", "CVE-2018-10853", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-15594", "CVE-2018-17972", "CVE-2018-5814", "CVE-2019-11091", "CVE-2019-11486", "CVE-2019-11815", "CVE-2019-11884", "CVE-2019-3882", "CVE-2019-9503");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-1407) (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)");
  script_summary(english:"Check for the openSUSE-2019-1407 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 kernel was updated to 4.4.179 to receive
various security and bugfixes.

Four new speculative execution information leak issues have been
identified in Intel CPUs. (bsc#1111331)

  - CVE-2018-12126: Microarchitectural Store Buffer Data
    Sampling (MSBDS)

  - CVE-2018-12127: Microarchitectural Fill Buffer Data
    Sampling (MFBDS)

  - CVE-2018-12130: Microarchitectural Load Port Data
    Samling (MLPDS)

  - CVE-2019-11091: Microarchitectural Data Sampling
    Uncacheable Memory (MDSUM)

This kernel update contains software mitigations for these issues,
which also utilize CPU microcode updates shipped in parallel.

For more information on this set of information leaks, check out
https://www.suse.com/support/kb/doc/?id=7023736

The following security bugs were fixed :

  - CVE-2018-5814: Multiple race condition errors when
    handling probe, disconnect, and rebind operations can be
    exploited to trigger a use-after-free condition or a
    NULL pointer dereference by sending multiple USB over IP
    packets (bnc#1096480).

  - CVE-2018-10853: A flaw was found in the way Linux kernel
    KVM hypervisor emulated instructions such as
    sgdt/sidt/fxsave/fxrstor. It did not check current
    privilege(CPL) level while emulating unprivileged
    instructions. An unprivileged guest user/process could
    use this flaw to potentially escalate privileges inside
    guest (bnc#1097104).

  - CVE-2018-15594: arch/x86/kernel/paravirt.c in the Linux
    kernel mishandled certain indirect calls, which made it
    easier for attackers to conduct Spectre-v2 attacks
    against paravirtual guests (bnc#1105348 1119974).

  - CVE-2018-17972: An issue was discovered in the
    proc_pid_stack function in fs/proc/base.c that did not
    ensure that only root may inspect the kernel stack of an
    arbitrary task, allowing a local attacker to exploit
    racy stack unwinding and leak kernel task stack contents
    (bnc#1110785).

  - CVE-2018-1000204: Prevent infoleak caused by incorrect
    handling of the SG_IO ioctl (bsc#1096728)

  - CVE-2019-11486: The Siemens R3964 line discipline driver
    in drivers/tty/n_r3964.c had multiple race conditions
    (bnc#1133188). It has been disabled.

  - CVE-2019-11815: An issue was discovered in
    rds_tcp_kill_sock in net/rds/tcp.c, a race condition
    leading to a use-after-free was fixed, related to net
    namespace cleanup (bnc#1134537).

  - CVE-2019-11884: The do_hidp_sock_ioctl function in
    net/bluetooth/hidp/sock.c allowed a local user to obtain
    potentially sensitive information from kernel stack
    memory via a HIDPCONNADD command, because a name field
    may not end with a '\0' character (bnc#1134848).

  - CVE-2019-3882: A flaw was found vfio interface
    implementation that permits violation of the user's
    locked memory limit. If a device is bound to a vfio
    driver, such as vfio-pci, and the local attacker is
    administratively granted ownership of the device, it may
    cause a system memory exhaustion and thus a denial of
    service (DoS). (bnc#1131416 bnc#1131427).

  - CVE-2019-9503: Multiple brcmfmac frame validation
    bypasses have been fixed (bnc#1132828).

The following non-security bugs were fixed :

  - 9p: do not trust pdu content for stat item size
    (bnc#1012382).

  - 9p locks: add mount option for lock retry interval
    (bnc#1012382).

  - 9p/net: fix memory leak in p9_client_create
    (bnc#1012382).

  - 9p: use inode->i_lock to protect i_size_write() under
    32-bit (bnc#1012382).

  - acpi: acpi_pad: Do not launch acpi_pad threads on idle
    cpus (bsc#1113399).

  - acpi / bus: Only call dmi_check_system() on X86
    (git-fixes).

  - acpi / button: make module loadable when booted in
    non-ACPI mode (bsc#1051510).

  - acpi / device_sysfs: Avoid OF modalias creation for
    removed device (bnc#1012382).

  - acpi / SBS: Fix GPE storm on recent MacBookPro's
    (bnc#1012382).

  - Add hlist_add_tail_rcu() (Merge
    git://git.kernel.org/pub/scm/linux/kernel/git/davem/net)
    (bnc#1012382).

  - alsa: bebob: use more identical mod_alias for Saffire
    Pro 10 I/O against Liquid Saffire 56 (bnc#1012382).

  - alsa: compress: add support for 32bit calls in a 64bit
    kernel (bnc#1012382).

  - alsa: compress: prevent potential divide by zero bugs
    (bnc#1012382).

  - alsa: core: Fix card races between register and
    disconnect (bnc#1012382).

  - alsa: echoaudio: add a check for ioremap_nocache
    (bnc#1012382).

  - alsa: hda - Enforces runtime_resume after S3 and S4 for
    each codec (bnc#1012382).

  - alsa: hda - Record the current power state before
    suspend/resume calls (bnc#1012382).

  - alsa: info: Fix racy addition/deletion of nodes
    (bnc#1012382).

  - alsa: opl3: fix mismatch between snd_opl3_drum_switch
    definition and declaration (bnc#1012382).

  - alsa: PCM: check if ops are defined before suspending
    PCM (bnc#1012382).

  - alsa: pcm: Do not suspend stream in unrecoverable PCM
    state (bnc#1012382).

  - alsa: pcm: Fix possible OOB access in PCM oss plugins
    (bnc#1012382).

  - alsa: rawmidi: Fix potential Spectre v1 vulnerability
    (bnc#1012382).

  - alsa: sb8: add a check for request_region (bnc#1012382).

  - alsa: seq: Fix OOB-reads from strlcpy (bnc#1012382).

  - alsa: seq: oss: Fix Spectre v1 vulnerability
    (bnc#1012382).

  - appletalk: Fix compile regression (bnc#1012382).

  - appletalk: Fix use-after-free in atalk_proc_exit
    (bnc#1012382).

  - applicom: Fix potential Spectre v1 vulnerabilities
    (bnc#1012382).

  - arc: fix __ffs return value to avoid build warnings
    (bnc#1012382).

  - arc: uacces: remove lp_start, lp_end from clobber list
    (bnc#1012382).

  - arcv2: Enable unaligned access in early ASM code
    (bnc#1012382).

  - arm64: Add helper to decode register from instruction
    (bsc#1126040).

  - arm64: debug: Do not propagate UNKNOWN FAR into si_code
    for debug signals (bnc#1012382).

  - arm64: debug: Ensure debug handlers check triggering
    exception level (bnc#1012382).

  - arm64: fix COMPAT_SHMLBA definition for large pages
    (bnc#1012382).

  - arm64: Fix NUMA build error when !CONFIG_ACPI
    (fate#319981, git-fixes).

  - arm64: Fix NUMA build error when !CONFIG_ACPI
    (git-fixes).

  - arm64: futex: Fix FUTEX_WAKE_OP atomic ops with non-zero
    result value (bnc#1012382).

  - arm64: futex: Restore oldval initialization to work
    around buggy compilers (bnc#1012382).

  - arm64: hide __efistub_ aliases from kallsyms
    (bnc#1012382).

  - arm64: kconfig: drop CONFIG_RTC_LIB dependency
    (bnc#1012382).

  - arm64/kernel: do not ban ADRP to work around Cortex-A53
    erratum #843419 (bsc#1126040).

  - arm64/kernel: fix incorrect EL0 check in inv_entry macro
    (bnc#1012382).

  - arm64/kernel: rename
    module_emit_adrp_veneer->module_emit_veneer_for_adrp
    (bsc#1126040).

  - arm64: mm: Add trace_irqflags annotations to
    do_debug_exception() (bnc#1012382).

  - arm64: module: do not BUG when exceeding preallocated
    PLT count (bsc#1126040).

  - arm64: module-plts: factor out PLT generation code for
    ftrace (bsc#1126040).

  - arm64: module: split core and init PLT sections
    (bsc#1126040).

  - arm64: Relax GIC version check during early boot
    (bnc#1012382).

  - arm64: support keyctl() system call in 32-bit mode
    (bnc#1012382).

  - arm64: traps: disable irq in die() (bnc#1012382).

  - arm: 8458/1: bL_switcher: add GIC dependency
    (bnc#1012382).

  - arm: 8494/1: mm: Enable PXN when running non-LPAE kernel
    on LPAE processor (bnc#1012382).

  - arm: 8510/1: rework ARM_CPU_SUSPEND dependencies
    (bnc#1012382).

  - arm: 8824/1: fix a migrating irq bug when hotplug cpu
    (bnc#1012382).

  - arm: 8833/1: Ensure that NEON code always compiles with
    Clang (bnc#1012382).

  - arm: 8839/1: kprobe: make patch_lock a raw_spinlock_t
    (bnc#1012382).

  - arm: 8840/1: use a raw_spinlock_t in unwind
    (bnc#1012382).

  - arm: avoid Cortex-A9 livelock on tight dmb loops
    (bnc#1012382).

  - arm: dts: at91: Fix typo in ISC_D0 on PC9 (bnc#1012382).

  - arm: dts: exynos: Add minimal clkout parameters to
    Exynos3250 PMU (bnc#1012382).

  - arm: dts: exynos: Do not ignore real-world fuse values
    for thermal zone 0 on Exynos5420 (bnc#1012382).

  - arm: imx6q: cpuidle: fix bug that CPU might not wake up
    at expected time (bnc#1012382).

  - arm: OMAP2+: Variable 'reg' in function
    omap4_dsi_mux_pads() could be uninitialized
    (bnc#1012382).

  - arm: pxa: ssp: unneeded to free devm_ allocated data
    (bnc#1012382).

  - arm: s3c24xx: Fix boolean expressions in
    osiris_dvs_notify (bnc#1012382).

  - arm: samsung: Limit SAMSUNG_PM_CHECK config option to
    non-Exynos platforms (bnc#1012382).

  - ASoC: dapm: change snprintf to scnprintf for possible
    overflow (bnc#1012382).

  - ASoC: fsl-asoc-card: fix object reference leaks in
    fsl_asoc_card_probe (bnc#1012382).

  - ASoC: fsl_esai: fix channel swap issue when stream
    starts (bnc#1012382).

  - ASoC: fsl_esai: fix register setting issue in RIGHT_J
    mode (bnc#1012382).

  - ASoC: imx-audmux: change snprintf to scnprintf for
    possible overflow (bnc#1012382).

  - ASoC: Intel: Haswell/Broadwell: fix setting for .dynamic
    field (bnc#1012382).

  - ASoC: topology: free created components in tplg load
    error (bnc#1012382).

  - assoc_array: Fix shortcut creation (bnc#1012382).

  - ath10k: avoid possible string overflow (bnc#1012382).

  - ath9k_htc: Add a sanity check in
    ath9k_htc_ampdu_action() (bsc#1087092).

  - atm: he: fix sign-extension overflow on large shift
    (bnc#1012382).

  - autofs: drop dentry reference only when it is never used
    (bnc#1012382).

  - autofs: fix error return in autofs_fill_super()
    (bnc#1012382).

  - batman-adv: Avoid endless loop in bat-on-bat netdevice
    check (git-fixes).

  - batman-adv: Fix lockdep annotation of
    batadv_tlv_container_remove (git-fixes).

  - batman-adv: fix uninit-value in batadv_interface_tx()
    (bnc#1012382).

  - batman-adv: Only put gw_node list reference when removed
    (git-fixes).

  - batman-adv: Only put orig_node_vlan list reference when
    removed (git-fixes).

  - bcache: account size of buckets used in uuid write to
    ca->meta_sectors_written (bsc#1130972).

  - bcache: add a comment in super.c (bsc#1130972).

  - bcache: add code comments for bset.c (bsc#1130972).

  - bcache: add comment for cache_set->fill_iter
    (bsc#1130972).

  - bcache: add identifier names to arguments of function
    definitions (bsc#1130972).

  - bcache: add missing SPDX header (bsc#1130972).

  - bcache: add MODULE_DESCRIPTION information
    (bsc#1130972).

  - bcache: add separate workqueue for journal_write to
    avoid deadlock (bsc#1130972).

  - bcache: add static const prefix to char * array
    declarations (bsc#1130972).

  - bcache: add sysfs_strtoul_bool() for setting bit-field
    variables (bsc#1130972).

  - bcache: add the missing comments for smp_mb()/smp_wmb()
    (bsc#1130972).

  - bcache: cannot set writeback_running via sysfs if no
    writeback kthread created (bsc#1130972).

  - bcache: comment on direct access to bvec table
    (bsc#1130972).

  - bcache: correct dirty data statistics (bsc#1130972).

  - bcache: do not assign in if condition in
    bcache_device_init() (bsc#1130972).

  - bcache: do not assign in if condition in bcache_init()
    (bsc#1130972).

  - bcache: do not assign in if condition register_bcache()
    (bsc#1130972).

  - bcache: do not check if debug dentry is ERR or NULL
    explicitly on remove (bsc#1130972).

  - bcache: do not check NULL pointer before calling
    kmem_cache_destroy (bsc#1130972).

  - bcache: do not clone bio in bch_data_verify
    (bsc#1130972).

  - bcache: do not mark writeback_running too early
    (bsc#1130972).

  - bcache: export backing_dev_name via sysfs (bsc#1130972).

  - bcache: export backing_dev_uuid via sysfs (bsc#1130972).

  - bcache: fix code comments style (bsc#1130972).

  - bcache: fix indentation issue, remove tabs on a hunk of
    code (bsc#1130972).

  - bcache: fix indent by replacing blank by tabs
    (bsc#1130972).

  - bcache: fix input integer overflow of congested
    threshold (bsc#1130972).

  - bcache: fix input overflow to cache set sysfs file
    io_error_halflife (bnc#1012382).

  - bcache: fix input overflow to journal_delay_ms
    (bsc#1130972).

  - bcache: fix input overflow to sequential_cutoff
    (bnc#1012382).

  - bcache: fix input overflow to writeback_delay
    (bsc#1130972).

  - bcache: fix input overflow to writeback_rate_minimum
    (bsc#1130972).

  - bcache: fix ioctl in flash device (bsc#1130972).

  - bcache: fix mistaken code comments in bcache.h
    (bsc#1130972).

  - bcache: fix mistaken comments in request.c
    (bsc#1130972).

  - bcache: fix potential div-zero error of
    writeback_rate_i_term_inverse (bsc#1130972).

  - bcache: fix potential div-zero error of
    writeback_rate_p_term_inverse (bsc#1130972).

  - bcache: fix typo in code comments of
    closure_return_with_destructor() (bsc#1130972).

  - bcache: fix typo 'succesfully' to 'successfully'
    (bsc#1130972).

  - bcache: improve sysfs_strtoul_clamp() (bnc#1012382).

  - bcache: introduce force_wake_up_gc() (bsc#1130972).

  - bcache: make cutoff_writeback and cutoff_writeback_sync
    tunable (bsc#1130972).

  - bcache: Move couple of functions to sysfs.c
    (bsc#1130972).

  - bcache: Move couple of string arrays to sysfs.c
    (bsc#1130972).

  - bcache: move open brace at end of function definitions
    to next line (bsc#1130972).

  - bcache: never writeback a discard operation
    (bsc#1130972).

  - bcache: not use hard coded memset size in
    bch_cache_accounting_clear() (bsc#1130972).

  - bcache: option to automatically run gc thread after
    writeback (bsc#1130972).

  - bcache: panic fix for making cache device (bsc#1130972).

  - bcache: Populate writeback_rate_minimum attribute
    (bsc#1130972).

  - bcache: prefer 'help' in Kconfig (bsc#1130972).

  - bcache: print number of keys in
    trace_bcache_journal_write (bsc#1130972).

  - bcache: recal cached_dev_sectors on detach
    (bsc#1130972).

  - bcache: remove unnecessary space before ioctl function
    pointer arguments (bsc#1130972).

  - bcache: remove unused bch_passthrough_cache
    (bsc#1130972).

  - bcache: remove useless parameter of bch_debug_init()
    (bsc#1130972).

  - bcache: replace hard coded number with BUCKET_GC_GEN_MAX
    (bsc#1130972).

  - bcache: replace '%pF' by '%pS' in seq_printf()
    (bsc#1130972).

  - bcache: replace printk() by pr_*() routines
    (bsc#1130972).

  - bcache: replace Symbolic permissions by octal permission
    numbers (bsc#1130972).

  - bcache: set writeback_percent in a flexible range
    (bsc#1130972).

  - bcache: split combined if-condition code into separate
    ones (bsc#1130972).

  - bcache: stop using the deprecated get_seconds()
    (bsc#1130972).

  - bcache: style fixes for lines over 80 characters
    (bsc#1130972).

  - bcache: style fix to add a blank line after declarations
    (bsc#1130972).

  - bcache: style fix to replace 'unsigned' by 'unsigned
    int' (bsc#1130972).

  - bcache: trace missed reading by cache_missed
    (bsc#1130972).

  - bcache: treat stale && dirty keys as bad keys
    (bsc#1130972).

  - bcache: trivial - remove tailing backslash in macro
    BTREE_FLAG (bsc#1130972).

  - bcache: update comment for bch_data_insert
    (bsc#1130972).

  - bcache: use MAX_CACHES_PER_SET instead of magic number 8
    in __bch_bucket_alloc_set (bsc#1130972).

  - bcache: use (REQ_META|REQ_PRIO) to indicate bio for
    metadata (bsc#1130972).

  - bcache: use REQ_PRIO to indicate bio for metadata
    (bsc#1130972).

  - bcache: use routines from lib/crc64.c for CRC64
    calculation (bsc#1130972).

  - bcache: use sysfs_strtoul_bool() to set bit-field
    variables (bsc#1130972).

  - bcache: writeback: properly order backing device IO
    (bsc#1130972).

  - binfmt_elf: switch to new creds when switching to new mm
    (bnc#1012382).

  - block: check_events: do not bother with events if
    unsupported (bsc#1110946).

  - block: disk_events: introduce event flags (bsc#1110946).

  - block: do not leak memory in bio_copy_user_iov()
    (bnc#1012382).

  - bluetooth: Check L2CAP option sizes returned from
    l2cap_get_conf_opt (bnc#1012382).

  - bluetooth: Fix decrementing reference count twice in
    releasing socket (bnc#1012382).

  - bnxt_en: Drop oversize TX packets to prevent errors
    (bnc#1012382).

  - bonding: fix event handling for stacked bonds
    (bnc#1012382).

  - btrfs: Avoid possible qgroup_rsv_size overflow in
    btrfs_calculate_inode_block_rsv_size (git-fixes).

  - btrfs: Do not panic when we can't find a root key
    (bsc#1112063).

  - btrfs: Fix bound checking in
    qgroup_trace_new_subtree_blocks (pending fix for
    bsc#1063638).

  - btrfs: fix corruption reading shared and compressed
    extents after hole punching (bnc#1012382).

  - btrfs: qgroup: Cleanup old subtree swap code
    (bsc#1063638).

  - btrfs: qgroup: Do not trace subtree if we're dropping
    reloc tree (bsc#1063638).

  - btrfs: qgroup: Introduce function to find all new tree
    blocks of reloc tree (bsc#1063638).

  - btrfs: qgroup: Introduce function to trace two swaped
    extents (bsc#1063638).

  - btrfs: qgroup: Introduce per-root swapped blocks
    infrastructure (bsc#1063638).

  - btrfs: qgroup: Introduce trace event to analyse the
    number of dirty extents accounted (bsc#1063638
    dependency).

  - btrfs: qgroup: Move reserved data accounting from
    btrfs_delayed_ref_head to btrfs_qgroup_extent_record
    (bsc#1134162).

  - btrfs: qgroup: Only trace data extents in leaves if
    we're relocating data block group (bsc#1063638).

  - btrfs: qgroup: Refactor btrfs_qgroup_trace_subtree_swap
    (bsc#1063638).

  - btrfs: qgroup: Remove duplicated trace points for
    qgroup_rsv_add/release (bsc#1134160).

  - btrfs: qgroup: Search commit root for rescan to avoid
    missing extent (bsc#1129326).

  - btrfs: qgroup: Use delayed subtree rescan for balance
    (bsc#1063638).

  - btrfs: qgroup: Use generation-aware subtree swap to mark
    dirty extents (bsc#1063638).

  - btrfs: raid56: properly unmap parity page in
    finish_parity_scrub() (bnc#1012382).

  - btrfs: relocation: Delay reloc tree deletion after
    merge_reloc_roots (bsc#1063638).

  - btrfs: reloc: Fix NULL pointer dereference due to
    expanded reloc_root lifespan (bsc#1134651).

  - btrfs: remove WARN_ON in log_dir_items (bnc#1012382).

  - cdc-wdm: pass return value of recover_from_urb_loss
    (bsc#1129770).

  - cdrom: Fix race condition in cdrom_sysctl_register
    (bnc#1012382).

  - ceph: ensure d_name stability in ceph_dentry_hash()
    (bsc#1134564).

  - ceph: fix ci->i_head_snapc leak (bsc#1122776).

  - ceph: fix use-after-free on symlink traversal
    (bsc#1134565).

  - ceph: only use d_name directly when parent is locked
    (bsc#1134566).

  - cfg80211: extend range deviation for DMG (bnc#1012382).

  - cfg80211: size various nl80211 messages correctly
    (bnc#1012382).

  - cifs: fallback to older infolevels on findfirst
    queryinfo retry (bnc#1012382).

  - cifs: fix computation for MAX_SMB2_HDR_SIZE
    (bnc#1012382).

  - cifs: Fix NULL pointer dereference of devname
    (bnc#1012382).

  - cifs: fix POSIX lock leak and invalid ptr deref
    (bsc#1114542).

  - cifs: Fix read after write for files with read caching
    (bnc#1012382).

  - cifs: use correct format characters (bnc#1012382).

  - clk: ingenic: Fix round_rate misbehaving with
    non-integer dividers (bnc#1012382).

  - clocksource/drivers/exynos_mct: Clear timer interrupt
    when shutdown (bnc#1012382).

  - clocksource/drivers/exynos_mct: Move one-shot check from
    tick clear to ISR (bnc#1012382).

  - cls_bpf: reset class and reuse major in da (git-fixes).

  - coresight: coresight_unregister() function cleanup
    (bnc#1012382).

  - coresight: 'DEVICE_ATTR_RO' should defined as static
    (bnc#1012382).

  - coresight: etm4x: Add support to enable ETMv4.2
    (bnc#1012382).

  - coresight: etm4x: Check every parameter used by
    dma_xx_coherent (bnc#1012382).

  - coresight: fixing lockdep error (bnc#1012382).

  - coresight: release reference taken by
    'bus_find_device()' (bnc#1012382).

  - coresight: remove csdev's link from topology
    (bnc#1012382).

  - coresight: removing bind/unbind options from sysfs
    (bnc#1012382).

  - cpufreq: pxa2xx: remove incorrect __init annotation
    (bnc#1012382).

  - cpufreq: tegra124: add missing of_node_put()
    (bnc#1012382).

  - cpufreq: Use struct kobj_attribute instead of struct
    global_attr (bnc#1012382).

  - cpu/hotplug: Handle unbalanced hotplug enable/disable
    (bnc#1012382).

  - cpu/speculation: Add 'mitigations=' cmdline option
    (bsc#1112178).

  - crypto: ahash - fix another early termination in hash
    walk (bnc#1012382).

  - crypto: arm64/aes-ccm - fix logical bug in AAD MAC
    handling (bnc#1012382).

  - crypto: caam - fixed handling of sg list (bnc#1012382).

  - crypto: crypto4xx - properly set IV after de- and
    encrypt (bnc#1012382).

  - crypto: pcbc - remove bogus memcpy()s with src == dest
    (bnc#1012382).

  - crypto: qat - remove unused and redundant pointer
    vf_info (bsc#1085539).

  - crypto: sha256/arm - fix crash bug in Thumb2 build
    (bnc#1012382).

  - crypto: sha512/arm - fix crash bug in Thumb2 build
    (bnc#1012382).

  - crypto: tgr192 - fix unaligned memory access
    (bsc#1129770).

  - crypto: x86/poly1305 - fix overflow during partial
    reduction (bnc#1012382).

  - cw1200: fix missing unlock on error in cw1200_hw_scan()
    (bsc#1129770).

  - dccp: do not use ipv6 header for ipv4 flow
    (bnc#1012382).

  - device_cgroup: fix RCU imbalance in error case
    (bnc#1012382).

  - Disable kgdboc failed by echo space to
    /sys/module/kgdboc/parameters/kgdboc (bnc#1012382).

  - dmaengine: at_xdmac: Fix wrongfull report of a channel
    as in use (bnc#1012382).

  - dmaengine: dmatest: Abort test in case of mapping error
    (bnc#1012382).

  - dmaengine: imx-dma: fix warning comparison of distinct
    pointer types (bnc#1012382).

  - dmaengine: tegra: avoid overflow of byte tracking
    (bnc#1012382).

  - dmaengine: usb-dmac: Make DMAC system sleep callbacks
    explicit (bnc#1012382).

  - dm: disable DISCARD if the underlying storage no longer
    supports it (bsc#1114638).

  - dm: fix to_sector() for 32bit (bnc#1012382).

  - dm thin: add sanity checks to thin-pool and external
    snapshot creation (bnc#1012382).

  - Drivers: hv: vmbus: Fix bugs in rescind handling
    (bsc#1130567).

  - Drivers: hv: vmbus: Fix ring buffer signaling
    (bsc#1118506).

  - Drivers: hv: vmbus: Fix the offer_in_progress in
    vmbus_process_offer() (bsc#1130567).

  - Drivers: hv: vmbus: Offload the handling of channels to
    two workqueues (bsc#1130567).

  - Drivers: hv: vmbus: Reset the channel callback in
    vmbus_onoffer_rescind() (bsc#1130567).

  - drm/dp/mst: Configure no_stop_bit correctly for remote
    i2c xfers (bnc#1012382).

  - drm/fb-helper: dpms_legacy(): Only set on connectors in
    use (bnc#1106929)

  - drm/i915: Fix I915_EXEC_RING_MASK (bnc#1106929)

  - drm/msm: Unblock writer if reader closes file
    (bnc#1012382).

  - drm/ttm: Remove warning about inconsistent mapping
    information (bnc#1131488)

  - drm/vc4: Account for interrupts in flight (bsc#1106929)

  - drm/vc4: Allocate the right amount of space for
    boot-time CRTC state. (bsc#1106929)

  - drm/vc4: fix a bounds check (bsc#1106929)

  - drm/vc4: Fix a couple error codes in vc4_cl_lookup_bos()
    (bsc#1106929)

  - drm/vc4: Fix compilation error reported by kbuild test
    bot (bsc#1106929)

  - drm/vc4: Fix memory leak during gpu reset. (bsc#1106929)

  - drm/vc4: Fix memory leak of the CRTC state.
    (bsc#1106929)

  - drm/vc4: Fix NULL pointer dereference in
    vc4_save_hang_state() (bsc#1106929)

  - drm/vc4: Fix OOPSes from trying to cache a partially
    constructed BO. (bsc#1106929)

  - drm/vc4: Fix oops when userspace hands in a bad BO.
    (bsc#1106929)

  - drm/vc4: Fix overflow mem unreferencing when the binner
    runs dry. (bsc#1106929)

  - drm/vc4: Fix races when the CS reads from render
    targets. (bsc#1106929)

  - drm/vc4: Fix scaling of uni-planar formats (bsc#1106929)

  - drm/vc4: Fix the 'no scaling' case on multi-planar YUV
    formats (bsc#1106929)

  - drm/vc4: Flush the caches before the bin jobs, as well.
    (bsc#1106929)

  - drm/vc4: Free hang state before destroying BO cache.
    (bsc#1106929)

  - drm/vc4: Move IRQ enable to PM path (bsc#1106929)

  - drm/vc4: Reset ->{x, y}_scaling[1] when dealing with
    uniplanar (bsc#1106929)

  - drm/vc4: Set ->is_yuv to false when num_planes == 1
    (bsc#1106929)

  - drm/vc4: Use drm_free_large() on handles to match its
    allocation. (bsc#1106929)

  - drm/vc4: ->x_scaling[1] should never be set to
    VC4_SCALING_NONE (bsc#1106929)

  - drm/vmwgfx: Do not double-free the mode stored in
    par->set_mode (bsc#1106929)

  - e1000e: Add Support for 38.4MHZ frequency (bsc#1108293
    ).

  - e1000e: Add Support for 38.4MHZ frequency (bsc#1108293
    fate#326719).

  - e1000e: Add Support for CannonLake (bsc#1108293).

  - e1000e: Add Support for CannonLake (bsc#1108293
    fate#326719).

  - e1000e: Fix -Wformat-truncation warnings (bnc#1012382).

  - e1000e: Initial Support for CannonLake (bsc#1108293 ).

  - e1000e: Initial Support for CannonLake (bsc#1108293
    fate#326719).

  - efi: stub: define DISABLE_BRANCH_PROFILING for all
    architectures (bnc#1012382).

  - enic: fix build warning without CONFIG_CPUMASK_OFFSTACK
    (bnc#1012382).

  - ext2: Fix underflow in ext2_max_size() (bnc#1012382).

  - ext4: add missing brelse() in add_new_gdb_meta_bg()
    (bnc#1012382).

  - ext4: Avoid panic during forced reboot (bsc#1126356).

  - ext4: brelse all indirect buffer in
    ext4_ind_remove_space() (bnc#1012382).

  - ext4: cleanup bh release code in ext4_ind_remove_space()
    (bnc#1012382).

  - ext4: fix data corruption caused by unaligned direct AIO
    (bnc#1012382).

  - ext4: fix NULL pointer dereference while journal is
    aborted (bnc#1012382).

  - ext4: prohibit fstrim in norecovery mode (bnc#1012382).

  - ext4: report real fs size after failed resize
    (bnc#1012382).

  - extcon: usb-gpio: Do not miss event during
    suspend/resume (bnc#1012382).

  - f2fs: do not use mutex lock in atomic context
    (bnc#1012382).

  - f2fs: fix to do sanity check with current segment number
    (bnc#1012382).

  - fbdev: fbmem: fix memory access if logo is bigger than
    the screen (bnc#1012382).

  - firmware: dmi: Optimize dmi_matches (git-fixes).

  - fix incorrect error code mapping for OBJECTID_NOT_FOUND
    (bnc#1012382).

  - floppy: check_events callback should not return a
    negative number (git-fixes).

  - flow_dissector: Check for IP fragmentation even if not
    using IPv4 address (git-fixes).

  - fs/9p: use fscache mutex rather than spinlock
    (bnc#1012382).

  - fs/file.c: initialize init_files.resize_wait
    (bnc#1012382).

  - fs: fix guard_bio_eod to check for real EOD errors
    (bnc#1012382).

  - fs/nfs: Fix nfs_parse_devname to not modify it's
    argument (git-fixes).

  - fs/proc/proc_sysctl.c: fix NULL pointer dereference in
    put_links (bnc#1012382).

  - fuse: continue to send FUSE_RELEASEDIR when FUSE_OPEN
    returns ENOSYS (git-fixes).

  - fuse: fix possibly missed wake-up after abort
    (git-fixes).

  - futex: Ensure that futex address is aligned in
    handle_futex_death() (bnc#1012382).

  - futex,rt_mutex: Fix rt_mutex_cleanup_proxy_lock()
    (git-fixes).

  - futex,rt_mutex: Restructure rt_mutex_finish_proxy_lock()
    (bnc#1012382).

  - genirq: Respect IRQCHIP_SKIP_SET_WAKE in
    irq_chip_set_wake_parent() (bnc#1012382).

  - gpio: adnp: Fix testing wrong value in
    adnp_gpio_direction_input (bnc#1012382).

  - gpio: gpio-omap: fix level interrupt idling
    (bnc#1012382).

  - gpio: vf610: Mask all GPIO interrupts (bnc#1012382).

  - gro_cells: make sure device is up in gro_cells_receive()
    (bnc#1012382).

  - h8300: use cc-cross-prefix instead of hardcoding
    h8300-unknown-linux- (bnc#1012382).

  - hid-sensor-hub.c: fix wrong do_div() usage
    (bnc#1012382).

  - hpet: Fix missing '=' character in the __setup() code of
    hpet_mmap_enable (bsc#1129770).

  - hugetlbfs: fix races and page leaks during migration
    (bnc#1012382).

  - hv_netvsc: Fix napi reschedule while receive completion
    is busy (bsc#1118506).

  - hv_netvsc: fix race in napi poll when rescheduling
    (bsc#1118506).

  - hv_netvsc: Fix the return status in RX path
    (bsc#1118506).

  - hv_netvsc: use napi_schedule_irqoff (bsc#1118506).

  - hv: v4.12 API for hyperv-iommu (bsc#1122822).

  - hv: v4.12 API for hyperv-iommu (fate#327171,
    bsc#1122822).

  - hwrng: virtio - Avoid repeated init of completion
    (bnc#1012382).

  - i2c: cadence: Fix the hold bit setting (bnc#1012382).

  - i2c: core-smbus: prevent stack corruption on read
    I2C_BLOCK_DATA (bnc#1012382).

  - i2c: tegra: fix maximum transfer size (bnc#1012382).

  - IB/{hfi1, qib}: Fix WC.byte_len calculation for
    UD_SEND_WITH_IMM (bnc#1012382).

  - IB/mlx4: Fix race condition between catas error reset
    and aliasguid flows (bnc#1012382).

  - IB/mlx4: Increase the timeout for CM cache
    (bnc#1012382).

  - ibmvnic: Enable GRO (bsc#1132227).

  - ibmvnic: Fix completion structure initialization
    (bsc#1131659).

  - ibmvnic: Fix netdev feature clobbering during a reset
    (bsc#1132227).

  - iio: adc: at91: disable adc channel interrupt in timeout
    case (bnc#1012382).

  - iio: ad_sigma_delta: select channel when reading
    register (bnc#1012382).

  - iio/gyro/bmg160: Use millidegrees for temperature scale
    (bnc#1012382).

  - Include ACPI button driver in base kernel (bsc#1062056).

  - include/linux/bitrev.h: fix constant bitrev
    (bnc#1012382).

  - include/linux/swap.h: use offsetof() instead of custom
    __swapoffset macro (bnc#1012382).

  - Input: elan_i2c - add id for touchpad found in Lenovo
    s21e-20 (bnc#1012382).

  - Input: matrix_keypad - use flush_delayed_work()
    (bnc#1012382).

  - Input: st-keyscan - fix potential zalloc NULL
    dereference (bnc#1012382).

  - Input: wacom_serial4 - add support for Wacom ArtPad II
    tablet (bnc#1012382).

  - intel_th: Do not reference unassigned outputs
    (bnc#1012382).

  - intel_th: gth: Fix an off-by-one in output unassigning
    (git-fixes).

  - io: accel: kxcjk1013: restore the range after resume
    (bnc#1012382).

  - iommu/amd: Fix NULL dereference bug in match_hid_uid
    (bsc#1130345).

  - iommu/amd: fix sg->dma_address for sg->offset bigger
    than PAGE_SIZE (bsc#1130346).

  - iommu/amd: Reserve exclusion range in iova-domain
    (bsc#1130425).

  - iommu/amd: Set exclusion range correctly (bsc#1130425).

  - iommu: Do not print warning when IOMMU driver only
    supports unmanaged domains (bsc#1130130).

  - iommu/hyper-v: Add Hyper-V stub IOMMU driver
    (bsc#1122822).

  - iommu/hyper-v: Add Hyper-V stub IOMMU driver
    (fate#327171, bsc#1122822).

  - iommu/vt-d: Check capability before disabling protected
    memory (bsc#1130347).

  - iommu/vt-d: Do not request page request irq under
    dmar_global_lock (bsc#1135013).

  - iommu/vt-d: Make kernel parameter igfx_off work with
    vIOMMU (bsc#1135014).

  - iommu/vt-d: Set intel_iommu_gfx_mapped correctly
    (bsc#1135015).

  - ip6: fix PMTU discovery when using /127 subnets
    (git-fixes).

  - ip6mr: Do not call __IP6_INC_STATS() from preemptible
    context (bnc#1012382).

  - ip6_tunnel: Match to ARPHRD_TUNNEL6 for dev type
    (bnc#1012382).

  - ip_tunnel: fix ip tunnel lookup in collect_md mode
    (git-fixes).

  - ipv4: add sanity checks in ipv4_link_failure()
    (git-fixes).

  - ipv4: ensure rcu_read_lock() in ipv4_link_failure()
    (bnc#1012382).

  - ipv4: recompile ip options in ipv4_link_failure
    (bnc#1012382).

  - ipv6: Fix dangling pointer when ipv6 fragment
    (bnc#1012382).

  - ipv6: sit: reset ip header pointer in ipip6_rcv
    (bnc#1012382).

  - ipvlan: disallow userns cap_net_admin to change global
    mode/flags (bnc#1012382).

  - ipvs: Fix signed integer overflow when setsockopt
    timeout (bnc#1012382).

  - irqchip/mmp: Only touch the PJ4 IRQ & FIQ bits on
    enable/disable (bnc#1012382).

  - iscsi_ibft: Fix missing break in switch statement
    (bnc#1012382).

  - isdn: avm: Fix string plus integer warning from Clang
    (bnc#1012382).

  - isdn: i4l: isdn_tty: Fix some concurrency double-free
    bugs (bnc#1012382).

  - isdn: isdn_tty: fix build warning of strncpy
    (bnc#1012382).

  - It's wrong to add len to sector_nr in raid10 reshape
    twice (bnc#1012382).

  - iwlwifi: dbg: do not crash if the firmware crashes in
    the middle of a debug dump (bsc#1119086).

  - jbd2: clear dirty flag when revoking a buffer from an
    older transaction (bnc#1012382).

  - jbd2: fix compile warning when using JBUFFER_TRACE
    (bnc#1012382).

  - kabi: arm64: fix kabi breakage on arch specific module
    (bsc#1126040)

  - kabi fixup gendisk disk_devt revert (bsc#1020989).

  - kbuild: clang: choose GCC_TOOLCHAIN_DIR not on LD
    (bnc#1012382).

  - kbuild: setlocalversion: print error to STDERR
    (bnc#1012382).

  - kernel/sysctl.c: add missing range check in
    do_proc_dointvec_minmax_conv (bnc#1012382).

  - kernel/sysctl.c: fix out-of-bounds access when setting
    file-max (bnc#1012382).

  - keys: allow reaching the keys quotas exactly
    (bnc#1012382).

  - keys: always initialize keyring_index_key::desc_len
    (bnc#1012382).

  - keys: restrict /proc/keys by credentials at open time
    (bnc#1012382).

  - keys: user: Align the payload buffer (bnc#1012382).

  - kprobes: Fix error check when reusing optimized probes
    (bnc#1012382).

  - kprobes: Mark ftrace mcount handler functions nokprobe
    (bnc#1012382).

  - kprobes: Prohibit probing on bsearch() (bnc#1012382).

  - kvm: Call kvm_arch_memslots_updated() before updating
    memslots (bsc#1132634).

  - kvm: nSVM: clear events pending from
    svm_complete_interrupts() when exiting to L1
    (bnc#1012382).

  - kvm: nVMX: Apply addr size mask to effective address for
    VMX instructions (bsc#1132635).

  - kvm: nVMX: Ignore limit checks on VMX instructions using
    flat segments (bnc#1012382).

  - kvm: nVMX: Sign extend displacements of VMX instr's mem
    operands (bnc#1012382).

  - kvm: Reject device ioctls from processes other than the
    VM's creator (bnc#1012382).

  - kvm: VMX: Compare only a single byte for VMCS'
    'launched' in vCPU-run (bsc#1132636).

  - kvm: VMX: Zero out *all* general purpose registers after
    VM-Exit (bsc#1132637).

  - kvm: x86: Do not clear EFER during SMM transitions for
    32-bit vCPU (bnc#1012382).

  - kvm: x86: Emulate MSR_IA32_ARCH_CAPABILITIES on AMD
    hosts (bsc#1132534).

  - kvm: X86: Fix residual mmio emulation request to
    userspace (bnc#1012382).

  - kvm: x86/mmu: Do not cache MMIO accesses while memslots
    are in flux (bsc#1132638).

  - l2tp: fix infoleak in l2tp_ip6_recvmsg() (git-fixes).

  - leds: lp5523: fix a missing check of return value of
    lp55xx_read (bnc#1012382).

  - leds: lp55xx: fix null deref on firmware load failure
    (bnc#1012382).

  - lib: add crc64 calculation routines (bsc#1130972).

  - lib/div64.c: off by one in shift (bnc#1012382).

  - lib: do not depend on linux headers being installed
    (bsc#1130972).

  - libertas: call into generic suspend code before turning
    off power (bsc#1106110).

  - libertas: fix suspend and resume for SDIO connected
    cards (bsc#1106110).

  - lib/int_sqrt: optimize initial value compute
    (bnc#1012382).

  - lib/int_sqrt: optimize small argument (bnc#1012382).

  - libnvdimm/pmem: Honor force_raw for legacy pmem regions
    (bsc#1131857).

  - lib/string.c: implement a basic bcmp (bnc#1012382).

  - locking/lockdep: Add debug_locks check in
    __lock_downgrade() (bnc#1012382).

  - locking/static_keys: Improve uninitialized key warning
    (bsc#1106913).

  - lpfc: validate command in
    lpfc_sli4_scmd_to_wqidx_distr() (bsc#1129138).

  - m68k: Add -ffreestanding to CFLAGS (bnc#1012382).

  - mac80211: do not call driver wake_tx_queue op during
    reconfig (bnc#1012382).

  - mac80211: do not initiate TDLS connection if station is
    not associated to AP (bnc#1012382).

  - mac80211: fix miscounting of ttl-dropped frames
    (bnc#1012382).

  - mac80211: fix 'warning: target metric may be used
    uninitialized' (bnc#1012382).

  - mac80211_hwsim: propagate genlmsg_reply return code
    (bnc#1012382).

  - mac8390: Fix mmio access size probe (bnc#1012382).

  - md: Fix failed allocation of md_register_thread
    (bnc#1012382).

  - mdio_bus: Fix use-after-free on device_register fails
    (bnc#1012382 git-fixes).

  - md/raid1: do not clear bitmap bits on interrupted
    recovery (git-fixes).

  - md: use mddev_suspend/resume instead of ->quiesce()
    (bsc#1132212).

  - media: cx88: Get rid of spurious call to
    cx8800_start_vbi_dma() (bsc#1100132).

  - media: mt9m111: set initial frame size other than 0x0
    (bnc#1012382).

  - media: mx2_emmaprp: Correct return type for mem2mem
    buffer helpers (bnc#1012382).

  - media: s5p-g2d: Correct return type for mem2mem buffer
    helpers (bnc#1012382).

  - media: s5p-jpeg: Check for fmt_ver_flag when doing fmt
    enumeration (bnc#1012382).

  - media: s5p-jpeg: Correct return type for mem2mem buffer
    helpers (bnc#1012382).

  - media: sh_veu: Correct return type for mem2mem buffer
    helpers (bnc#1012382).

  - media: uvcvideo: Avoid NULL pointer dereference at the
    end of streaming (bnc#1012382).

  - media: uvcvideo: Fix 'type' check leading to overflow
    (bnc#1012382).

  - media: uvcvideo: Fix uvc_alloc_entity() allocation
    alignment (bsc#1119086).

  - media: v4l2-ctrls.c/uvc: zero v4l2_event (bnc#1012382).

  - media: vb2: do not call __vb2_queue_cancel if
    vb2_start_streaming failed (bsc#1120902).

  - media: videobuf2-v4l2: drop WARN_ON in
    vb2_warn_zero_bytesused() (bnc#1012382).

  - media: vivid: potential integer overflow in
    vidioc_g_edid() (bsc#11001132).

  - mfd: ab8500-core: Return zero in
    get_register_interruptible() (bnc#1012382).

  - mfd: db8500-prcmu: Fix some section annotations
    (bnc#1012382).

  - mfd: mc13xxx: Fix a missing check of a register-read
    failure (bnc#1012382).

  - mfd: qcom_rpm: write fw_version to CTRL_REG
    (bnc#1012382).

  - mfd: ti_am335x_tscadc: Use PLATFORM_DEVID_AUTO while
    registering mfd cells (bnc#1012382).

  - mfd: twl-core: Fix section annotations on
    {,un}protect_pm_master (bnc#1012382).

  - mfd: wm5110: Add missing ASRC rate register
    (bnc#1012382).

  - mips: ath79: Enable OF serial ports in the default
    config (bnc#1012382).

  - mips: Fix kernel crash for R6 in jump label branch
    function (bnc#1012382).

  - mips: irq: Allocate accurate order pages for irq stack
    (bnc#1012382).

  - mips: jazz: fix 64bit build (bnc#1012382).

  - mips: loongson64: lemote-2f: Add IRQF_NO_SUSPEND to
    'cascade' irqaction (bnc#1012382).

  - mips: Remove function size check in get_frame_info()
    (bnc#1012382).

  - mISDN: hfcpci: Test both vendor & device ID for Digium
    HFC4S (bnc#1012382).

  - missing barriers in some of unix_sock ->addr and ->path
    accesses (bnc#1012382).

  - mmc: bcm2835: reset host on timeout (bsc#1070872).

  - mmc: block: Allow more than 8 partitions per card
    (bnc#1012382).

  - mmc: core: fix using wrong io voltage if
    mmc_select_hs200 fails (bnc#1012382).

  - mmc: core: shut up 'voltage-ranges unspecified'
    pr_info() (bnc#1012382).

  - mmc: davinci: remove extraneous __init annotation
    (bnc#1012382).

  - mmc: debugfs: Add a restriction to mmc debugfs clock
    setting (bnc#1012382).

  - mm/cma.c: cma_declare_contiguous: correct err handling
    (bnc#1012382).

  - mmc: make MAN_BKOPS_EN message a debug (bnc#1012382).

  - mmc: mmc: fix switch timeout issue caused by jiffies
    precision (bnc#1012382).

  - mmc: omap: fix the maximum timeout setting
    (bnc#1012382).

  - mmc: pwrseq_simple: Make reset-gpios optional to match
    doc (bnc#1012382).

  - mmc: pxamci: fix enum type confusion (bnc#1012382).

  - mmc: sanitize 'bus width' in debug output (bnc#1012382).

  - mmc: spi: Fix card detection during probe (bnc#1012382).

  - mmc: tmio_mmc_core: do not claim spurious interrupts
    (bnc#1012382).

  - mm/debug.c: fix __dump_page when mapping->host is not
    set (bsc#1131934).

  - mm, memory_hotplug: fix off-by-one in
    is_pageblock_removable (git-fixes).

  - mm, memory_hotplug: is_mem_section_removable do not pass
    the end of a zone (bnc#1012382).

  - mm, memory_hotplug: test_pages_in_a_zone do not pass the
    end of zone (bnc#1012382).

  - mm: mempolicy: make mbind() return -EIO when
    MPOL_MF_STRICT is specified (bnc#1012382).

  - mm: move is_pageblock_removable_nolock() to
    mm/memory_hotplug.c (git-fixes prerequisity).

  - mm/page_ext.c: fix an imbalance with kmemleak
    (bnc#1012382).

  - mm/page_isolation.c: fix a wrong flag in
    set_migratetype_isolate() (bsc#1131935)

  - mm/rmap: replace BUG_ON(anon_vma->degree) with
    VM_WARN_ON (bnc#1012382).

  - mm/slab.c: kmemleak no scan alien caches (bnc#1012382).

  - mm/vmalloc.c: fix kernel BUG at mm/vmalloc.c:512!
    (bnc#1012382).

  - mm/vmalloc: fix size check for
    remap_vmalloc_range_partial() (bnc#1012382).

  - mm/vmstat.c: fix /proc/vmstat format for
    CONFIG_DEBUG_TLBFLUSH=y CONFIG_SMP=n (bnc#1012382).

  - modpost: file2alias: check prototype of handler
    (bnc#1012382).

  - modpost: file2alias: go back to simple devtable lookup
    (bnc#1012382).

  - move power_up_on_resume flag to end of structure for
    kABI (bsc#1106110).

  - mt7601u: bump supported EEPROM version (bnc#1012382).

  - mtd: Fix comparison in map_word_andequal() (git-fixes).

  - mwifiex: pcie: tighten a check in
    mwifiex_pcie_process_event_ready() (bsc#1100132).

  - ncpfs: fix build warning of strncpy (bnc#1012382).

  - net: add description for len argument of
    dev_get_phys_port_name (git-fixes).

  - net: Add __icmp_send helper (bnc#1012382).

  - net: altera_tse: fix connect_local_phy error path
    (bnc#1012382).

  - net: altera_tse: fix msgdma_tx_completion on non-zero
    fill_level case (bnc#1012382).

  - net: atm: Fix potential Spectre v1 vulnerabilities
    (bnc#1012382).

  - net: avoid use IPCB in cipso_v4_error (bnc#1012382).

  - net: bridge: multicast: use rcu to access port list from
    br_multicast_start_querier (bnc#1012382).

  - net: diag: support v4mapped sockets in
    inet_diag_find_one_icsk() (bnc#1012382).

  - net: do not decrement kobj reference count on init
    failure (git-fixes).

  - net: dsa: mv88e6xxx: Fix u64 statistics (bnc#1012382).

  - net: ena: fix race between link up and device
    initalization (bsc#1129278).

  - net: ena: update driver version from 2.0.2 to 2.0.3
    (bsc#1129278).

  - net: ethtool: not call vzalloc for zero sized memory
    request (bnc#1012382).

  - netfilter: ipt_CLUSTERIP: fix use-after-free of proc
    entry (git-fixes).

  - netfilter: nf_conntrack_tcp: Fix stack out of bounds
    when parsing TCP options (bnc#1012382).

  - netfilter: nfnetlink_acct: validate NFACCT_FILTER
    parameters (bnc#1012382).

  - netfilter: nfnetlink_log: just returns error for unknown
    command (bnc#1012382).

  - netfilter: nfnetlink: use original skbuff when acking
    batches (git-fixes).

  - netfilter: physdev: relax br_netfilter dependency
    (bnc#1012382).

  - netfilter: x_tables: enforce nul-terminated table name
    from getsockopt GET_ENTRIES (bnc#1012382).

  - net: fou: do not use guehdr after iptunnel_pull_offloads
    in gue_udp_recv (bnc#1012382).

  - net: hns: Fix use after free identified by SLUB debug
    (bnc#1012382).

  - net: hns: Fix wrong read accesses via Clause 45 MDIO
    protocol (bnc#1012382).

  - net: hsr: fix memory leak in hsr_dev_finalize()
    (bnc#1012382).

  - net/hsr: fix possible crash in add_timer()
    (bnc#1012382).

  - net/ibmvnic: Update carrier state after link state
    change (bsc#1135100).

  - net/ibmvnic: Update MAC address settings after adapter
    reset (bsc#1134760).

  - netlabel: fix out-of-bounds memory accesses
    (bnc#1012382).

  - net/mlx4_en: Force CHECKSUM_NONE for short ethernet
    frames (bnc#1012382).

  - net: mv643xx_eth: disable clk on error path in
    mv643xx_eth_shared_probe() (bnc#1012382).

  - net: nfc: Fix NULL dereference on nfc_llcp_build_tlv
    fails (bnc#1012382).

  - netns: provide pure entropy for net_hash_mix()
    (bnc#1012382).

  - net/packet: fix 4gb buffer limit due to overflow check
    (bnc#1012382).

  - net/packet: Set __GFP_NOWARN upon allocation in
    alloc_pg_vec (bnc#1012382).

  - net: phy: Micrel KSZ8061: link failure after cable
    connect (bnc#1012382).

  - net: rds: force to destroy connection if t_sock is NULL
    in rds_tcp_kill_sock() (bnc#1012382).

  - net: rose: fix a possible stack overflow (bnc#1012382).

  - net: Set rtm_table to RT_TABLE_COMPAT for ipv6 for
    tables > 255 (bnc#1012382).

  - net: set static variable an initial value in
    atl2_probe() (bnc#1012382).

  - net: sit: fix UBSAN Undefined behaviour in check_6rd
    (bnc#1012382).

  - net: stmmac: dwmac-rk: fix error handling in
    rk_gmac_powerup() (bnc#1012382).

  - net-sysfs: call dev_hold if kobject_init_and_add success
    (git-fixes).

  - net-sysfs: Fix mem leak in netdev_register_kobject
    (bnc#1012382).

  - net: systemport: Fix reception of BPDUs (bnc#1012382).

  - net: tcp_memcontrol: properly detect ancestor socket
    pressure (git-fixes).

  - net/x25: fix a race in x25_bind() (bnc#1012382).

  - net/x25: fix use-after-free in x25_device_event()
    (bnc#1012382).

  - net/x25: reset state in x25_connect() (bnc#1012382).

  - NFC: nci: memory leak in nci_core_conn_create()
    (git-fixes).

  - nfs41: pop some layoutget errors to application
    (bnc#1012382).

  - nfs: Add missing encode / decode sequence_maxsz to v4.2
    operations (git-fixes).

  - nfs: clean up rest of reqs when failing to add one
    (git-fixes).

  - nfsd: fix memory corruption caused by readdir
    (bsc#1127445).

  - nfsd: fix wrong check in write_v4_end_grace()
    (git-fixes).

  - nfs: Do not recoalesce on error in
    nfs_pageio_complete_mirror() (git-fixes).

  - nfs: Fix an I/O request leakage in nfs_do_recoalesce
    (git-fixes).

  - nfs: Fix dentry revalidation on NFSv4 lookup
    (bsc#1132618).

  - nfs: Fix I/O request leakages (git-fixes).

  - nfs: fix mount/umount race in nlmclnt (git-fixes).

  - nfs: Fix NULL pointer dereference of dev_name
    (bnc#1012382).

  - nfs/pnfs: Bulk destroy of layouts needs to be safe
    w.r.t. umount (git-fixes).

  - nfsv4.x: always serialize open/close operations
    (bsc#1114893).

  - numa: change get_mempolicy() to use nr_node_ids instead
    of MAX_NUMNODES (bnc#1012382).

  - nvme-fc: resolve io failures during connect
    (bsc#1116803).

  - ocfs2: fix a panic problem caused by o2cb_ctl
    (bnc#1012382).

  - openvswitch: fix flow actions reallocation
    (bnc#1012382).

  - packets: Always register packet sk in the same order
    (bnc#1012382).

  - parport_pc: fix find_superio io compare code, should use
    equal test (bnc#1012382).

  - pci: Add function 1 DMA alias quirk for Marvell 9170
    SATA controller (bnc#1012382).

  - pci-hyperv: increase HV_VP_SET_BANK_COUNT_MAX to handle
    1792 vcpus (bsc#1122822).

  - pci-hyperv: increase HV_VP_SET_BANK_COUNT_MAX to handle
    1792 vcpus (fate#327171, bsc#1122822).

  - pci: xilinx-nwl: Add missing of_node_put()
    (bsc#1100132).

  - perf auxtrace: Define auxtrace record alignment
    (bnc#1012382).

  - perf bench: Copy kernel files needed to build
    mem{cpy,set} x86_64 benchmarks (bnc#1012382).

  - perf/core: Restore mmap record type correctly
    (bnc#1012382).

  - perf evsel: Free evsel->counts in perf_evsel__exit()
    (bnc#1012382).

  - perf intel-pt: Fix CYC timestamp calculation after OVF
    (bnc#1012382).

  - perf intel-pt: Fix overlap calculation for padding
    (bnc#1012382).

  - perf intel-pt: Fix TSC slip (bnc#1012382).

  - perf/ring_buffer: Refuse to begin AUX transaction after
    rb->aux_mmap_count drops (bnc#1012382).

  - perf symbols: Filter out hidden symbols from labels
    (bnc#1012382).

  - perf: Synchronously free aux pages in case of allocation
    failure (bnc#1012382).

  - perf test: Fix failure of 'evsel-tp-sched' test on s390
    (bnc#1012382).

  - perf tests: Fix a memory leak in
    test__perf_evsel__tp_sched_test() (bnc#1012382).

  - perf tests: Fix a memory leak of cpu_map object in the
    openat_syscall_event_on_all_cpus test (bnc#1012382).

  - perf tools: Handle TOPOLOGY headers with no CPU
    (bnc#1012382).

  - perf top: Fix error handling in cmd_top() (bnc#1012382).

  - perf/x86/amd: Add event map for AMD Family 17h
    (bsc#1114648).

  - phonet: fix building with clang (bnc#1012382).

  - pinctrl: meson: meson8b: fix the sdxc_a data 1..3 pins
    (bnc#1012382).

  - platform/x86: Fix unmet dependency warning for
    SAMSUNG_Q10 (bnc#1012382).

  - PM / Hibernate: Call flush_icache_range() on pages
    restored in-place (bnc#1012382).

  - PM / wakeup: Rework wakeup source timer cancellation
    (bnc#1012382).

  - pNFS: Skip invalid stateids when doing a bulk destroy
    (git-fixes).

  - powerpc/32: Clear on-stack exception marker upon
    exception return (bnc#1012382).

  - powerpc/64: Call setup_barrier_nospec() from
    setup_arch() (bsc#1131107).

  - powerpc/64: Disable the speculation barrier from the
    command line (bsc#1131107).

  - powerpc/64: Make stf barrier PPC_BOOK3S_64 specific
    (bsc#1131107).

  - powerpc/64s: Add new security feature flags for count
    cache flush (bsc#1131107).

  - powerpc/64s: Add support for software count cache flush
    (bsc#1131107).

  - powerpc/83xx: Also save/restore SPRG4-7 during suspend
    (bnc#1012382).

  - powerpc: Always initialize input array when calling
    epapr_hypercall() (bnc#1012382).

  - powerpc/asm: Add a patch_site macro & helpers for
    patching instructions (bsc#1131107).

  - powerpc/fsl: Fix spectre_v2 mitigations reporting
    (bsc#1131107).

  - powerpc/mm/hash: Handle mmap_min_addr correctly in
    get_unmapped_area topdown search (bsc#1131900).

  - powerpc/numa: document topology_updates_enabled, disable
    by default (bsc#1133584).

  - powerpc/numa: improve control of topology updates
    (bsc#1133584).

  - powerpc/perf: Fix unit_sel/cache_sel checks
    (bsc#1053043).

  - powerpc/perf: Remove l2 bus events from HW cache event
    array (bsc#1053043).

  - powerpc/perf: Update raw-event code encoding comment for
    power8 (bsc#1053043, git-fixes).

  - powerpc/powernv/cpuidle: Init all present cpus for deep
    states (bsc#1066223).

  - powerpc/powernv: Make opal log only readable by root
    (bnc#1012382).

  - powerpc/powernv: Query firmware for count cache flush
    settings (bsc#1131107).

  - powerpc/pseries/mce: Fix misleading print for TLB
    mutlihit (bsc#1094244, git-fixes).

  - powerpc/pseries: Query hypervisor for count cache flush
    settings (bsc#1131107).

  - powerpc/security: Fix spectre_v2 reporting
    (bsc#1131107).

  - powerpc/speculation: Support 'mitigations=' cmdline
    option (bsc#1112178).

  - powerpc/tm: Add commandline option to disable hardware
    transactional memory (bsc#1118338).

  - powerpc/tm: Add TM Unavailable Exception (bsc#1118338).

  - powerpc/tm: Flip the HTM switch default to disabled
    (bsc#1125580).

  - powerpc/vdso32: fix CLOCK_MONOTONIC on PPC64
    (bsc#1131587).

  - powerpc/vdso64: Fix CLOCK_MONOTONIC inconsistencies
    across Y2038 (bsc#1131587).

  - powerpc/wii: properly disable use of BATs when requested
    (bnc#1012382).

  - qmi_wwan: add Olicard 600 (bnc#1012382).

  - ravb: Decrease TxFIFO depth of Q3 and Q2 to one
    (bnc#1012382).

  - rcu: Do RCU GP kthread self-wakeup from softirq and
    interrupt (bnc#1012382).

  - RDMA/core: Do not expose unsupported counters
    (bsc#994770).

  - RDMA/srp: Rework SCSI device reset handling
    (bnc#1012382).

  - regulator: act8865: Fix act8600_sudcdc_voltage_ranges
    setting (bnc#1012382).

  - regulator: s2mpa01: Fix step values for some LDOs
    (bnc#1012382).

  - regulator: s2mps11: Fix steps for buck7, buck8 and LDO35
    (bnc#1012382).

  - Revert 'block: unexport DISK_EVENT_MEDIA_CHANGE for
    legacy/fringe drivers' (bsc#1110946).

  - Revert 'bridge: do not add port to router list when
    receives query with source 0.0.0.0' (bnc#1012382).

  - Revert 'ide: unexport DISK_EVENT_MEDIA_CHANGE for ide-gd
    and ide-cd' (bsc#1110946).

  - Revert 'ipv4: keep skb->dst around in presence of IP
    options' (git-fixes).

  - Revert 'kbuild: use -Oz instead of -Os when using clang'
    (bnc#1012382).

  - Revert 'KEYS: restrict /proc/keys by credentials at open
    time' (kabi).

  - Revert 'locking/lockdep: Add debug_locks check in
    __lock_downgrade()' (bnc#1012382).

  - Revert 'mmc: block: do not use parameter prefix if built
    as module' (bnc#1012382).

  - Revert 'netns: provide pure entropy for net_hash_mix()'
    (kabi).

  - Revert 'scsi, block: fix duplicate bdi name registration
    crashes' (bsc#1020989).

  - Revert 'USB: core: only clean up what we allocated'
    (bnc#1012382).

  - Revert 'x86/kprobes: Verify stack frame on kretprobe'
    (kabi).

  - route: set the deleted fnhe fnhe_daddr to 0 in
    ip_del_fnhe to fix a race (bnc#1012382).

  - rsi: fix a dereference on adapter before it has been
    null checked (bsc#1085539).

  - rsi: improve kernel thread handling to fix kernel panic
    (bnc#1012382).

  - rtc: Fix overflow when converting time64_t to rtc_time
    (bnc#1012382).

  - rtl8xxxu: Fix missing break in switch (bsc#1120902).

  - s390/dasd: fix panic for failed online processing
    (bsc#1132589).

  - s390/dasd: fix using offset into zero size array error
    (bnc#1012382).

  - s390: Prevent hotplug rwsem recursion (bsc#1131980).

  - s390/qeth: fix use-after-free in error path
    (bnc#1012382).

  - s390/speculation: Support 'mitigations=' cmdline option
    (bsc#1112178).

  - s390/virtio: handle find on invalid queue gracefully
    (bnc#1012382).

  - sched/core: Fix cpu.max vs. cpuhotplug deadlock
    (bsc#1106913).

  - sched/fair: Do not re-read ->h_load_next during
    hierarchical load calculation (bnc#1012382).

  - sched/fair: Limit sched_cfs_period_timer() loop to avoid
    hard lockup (bnc#1012382).

  - sched/smt: Expose sched_smt_present static key
    (bsc#1106913).

  - sched/smt: Make sched_smt_present track topology
    (bsc#1106913).

  - scripts/git_sort/git_sort.py: Add fixes branch from
    mkp/scsi.git.

  - scsi: core: replace GFP_ATOMIC with GFP_KERNEL in
    scsi_scan.c (bnc#1012382).

  - scsi: csiostor: fix NULL pointer dereference in
    csio_vport_set_state() (bnc#1012382).

  - scsi: isci: initialize shost fully before calling
    scsi_add_host() (bnc#1012382).

  - scsi: libfc: free skb when receiving invalid flogi resp
    (bnc#1012382).

  - scsi: libiscsi: Fix race between iscsi_xmit_task and
    iscsi_complete_task (bnc#1012382).

  - scsi: libsas: Fix rphy phy_identifier for PHYs with end
    devices attached (bnc#1012382).

  - scsi: megaraid_sas: return error when create DMA pool
    failed (bnc#1012382).

  - scsi: qla4xxx: check return code of
    qla4xxx_copy_from_fwddb_param (bnc#1012382).

  - scsi: sd: Fix a race between closing an sd device and sd
    I/O (bnc#1012382).

  - scsi: storvsc: Fix a race in sub-channel creation that
    can cause panic ().

  - scsi: storvsc: Fix a race in sub-channel creation that
    can cause panic (fate#323887).

  - scsi: storvsc: Reduce default ring buffer size to 128
    Kbytes ().

  - scsi: storvsc: Reduce default ring buffer size to 128
    Kbytes (fate#323887).

  - scsi: target/iscsi: Avoid
    iscsit_release_commands_from_conn() deadlock
    (bnc#1012382).

  - scsi: virtio_scsi: do not send sc payload with tmfs
    (bnc#1012382).

  - scsi: zfcp: fix rport unblock if deleted SCSI devices on
    Scsi_Host (bnc#1012382).

  - scsi: zfcp: fix scsi_eh host reset with port_forced ERP
    for non-NPIV FCP devices (bnc#1012382).

  - sctp: fix the transports round robin issue when init is
    retransmitted (git-fixes).

  - sctp: get sctphdr by offset in sctp_compute_cksum
    (bnc#1012382).

  - sctp: initialize _pad of sockaddr_in before copying to
    user memory (bnc#1012382).

  - serial: 8250_pci: Fix number of ports for ACCES serial
    cards (bnc#1012382).

  - serial: 8250_pci: Have ACCES cards that use the four
    port Pericom PI7C9X7954 chip use the pci_pericom_setup()
    (bnc#1012382).

  - serial: fsl_lpuart: fix maximum acceptable baud rate
    with over-sampling (bnc#1012382).

  - serial: max310x: Fix to avoid potential NULL pointer
    dereference (bnc#1012382).

  - serial: sh-sci: Fix setting SCSCR_TIE while transferring
    data (bnc#1012382).

  - serial: sprd: adjust TIMEOUT to a big value
    (bnc#1012382).

  - serial: sprd: clear timeout interrupt only rather than
    all interrupts (bnc#1012382).

  - serial: uartps: console_setup() can't be placed to init
    section (bnc#1012382).

  - sit: check if IPv6 enabled before calling
    ip6_err_gen_icmpv6_unreach() (bnc#1012382).

  - sky2: Disable MSI on Dell Inspiron 1545 and Gateway P-79
    (bnc#1012382).

  - SoC: imx-sgtl5000: add missing put_device()
    (bnc#1012382).

  - sockfs: getxattr: Fail with -EOPNOTSUPP for invalid
    attribute names (bnc#1012382).

  - soc: qcom: gsbi: Fix error handling in gsbi_probe()
    (bnc#1012382).

  - soc/tegra: fuse: Fix illegal free of IO base address
    (bnc#1012382).

  - staging: ashmem: Add missing include (bnc#1012382).

  - staging: ashmem: Avoid deadlock with mmap/shrink
    (bnc#1012382).

  - staging: comedi: ni_usb6501: Fix possible double-free of
    ->usb_rx_buf (bnc#1012382).

  - staging: comedi: ni_usb6501: Fix use of uninitialized
    mutex (bnc#1012382).

  - staging: comedi: vmk80xx: Fix possible double-free of
    ->usb_rx_buf (bnc#1012382).

  - staging: comedi: vmk80xx: Fix use of uninitialized
    semaphore (bnc#1012382).

  - staging: goldfish: audio: fix compiliation on arm
    (bnc#1012382).

  - staging: ion: Set minimum carveout heap allocation order
    to PAGE_SHIFT (bnc#1012382).

  - staging: lustre: fix buffer overflow of string buffer
    (bnc#1012382).

  - staging: rtl8188eu: avoid a null dereference on
    pmlmepriv (bsc#1085539).

  - staging: vt6655: Fix interrupt race condition on device
    start up (bnc#1012382).

  - staging: vt6655: Remove vif check from vnt_interrupt
    (bnc#1012382).

  - stm class: Do not leak the chrdev in error path
    (bnc#1012382).

  - stm class: Fix an endless loop in channel allocation
    (bnc#1012382).

  - stm class: Fix a race in unlinking (bnc#1012382).

  - stm class: Fix link list locking (bnc#1012382).

  - stm class: Fix locking in unbinding policy path
    (bnc#1012382).

  - stm class: Fix stm device initialization order
    (bnc#1012382).

  - stm class: Fix unbalanced module/device refcounting
    (bnc#1012382).

  - stm class: Fix unlocking braino in the error path
    (bnc#1012382).

  - stm class: Guard output assignment against concurrency
    (bnc#1012382).

  - stm class: Hide STM-specific options if STM is disabled
    (bnc#1012382).

  - stm class: Prevent division by zero (bnc#1012382).

  - stm class: Prevent user-controllable allocations
    (bnc#1012382).

  - stm class: Support devices with multiple instances
    (bnc#1012382).

  - stmmac: copy unicast mac address to MAC registers
    (bnc#1012382).

  - stop_machine: Provide stop_machine_cpuslocked()
    (bsc#1131980).

  - sunrpc: do not mark uninitialised items as VALID
    (bsc#1130737).

  - sunrpc: init xdr_stream for zero iov_len, page_len
    (bsc#11303356).

  - supported.conf: add lib/crc64 because bcache uses it

  - svm/avic: Fix invalidate logical APIC id entry
    (bsc#1132727).

  - svm: Fix AVIC DFR and LDR handling (bsc#1130343).

  - svm: Fix improper check when deactivate AVIC
    (bsc#1130344).

  - sysctl: handle overflow for file-max (bnc#1012382).

  - tcp/dccp: drop SYN packets if accept queue is full
    (bnc#1012382).

  - tcp/dccp: remove reqsk_put() from inet_child_forget()
    (git-fixes).

  - tcp: do not use ipv6 header for ipv4 flow (bnc#1012382).

  - tcp: Ensure DCTCP reacts to losses (bnc#1012382).

  - tcp: handle inet_csk_reqsk_queue_add() failures
    (git-fixes).

  - tcp: tcp_grow_window() needs to respect tcp_space()
    (bnc#1012382).

  - thermal/int340x_thermal: Add additional UUIDs
    (bnc#1012382).

  - thermal: int340x_thermal: Fix a NULL vs IS_ERR() check
    (bnc#1012382).

  - thermal/int340x_thermal: fix mode setting (bnc#1012382).

  - time: Introduce jiffies64_to_nsecs() (bsc#1113399).

  - tmpfs: fix link accounting when a tmpfile is linked in
    (bnc#1012382).

  - tmpfs: fix uninitialized return value in shmem_link
    (bnc#1012382).

  - tools lib traceevent: Fix buffer overflow in arg_eval
    (bnc#1012382).

  - tools/power turbostat: return the exit status of a
    command (bnc#1012382).

  - tpm: fix kdoc for tpm2_flush_context_cmd()
    (bsc#1020645).

  - tpm: Fix the type of the return value in
    calc_tpm2_event_size() (bsc#1020645, git-fixes).

  - tpm/tpm_crb: Avoid unaligned reads in crb_recv()
    (bnc#1012382).

  - tpm/tpm_i2c_atmel: Return -E2BIG when the transfer is
    incomplete (bnc#1012382).

  - tpm: tpm-interface.c drop unused macros (bsc#1020645).

  - tracing: kdb: Fix ftdump to not sleep (bnc#1012382).

  - tty: atmel_serial: fix a potential NULL pointer
    dereference (bnc#1012382).

  - tty: increase the default flip buffer limit to 2*640K
    (bnc#1012382).

  - tty: ldisc: add sysctl to prevent autoloading of ldiscs
    (bnc#1012382).

  - tty/serial: atmel: Add is_half_duplex helper
    (bnc#1012382).

  - tty/serial: atmel: RS485 HD w/DMA: enable RX after TX is
    stopped (bnc#1012382).

  - uas: fix alignment of scatter/gather segments
    (bsc#1129770).

  - udf: Fix crash on IO error during truncate
    (bnc#1012382).

  - Update config files: add CONFIG_CRC64=m

  - usb: Add new USB LPM helpers (bsc#1129770).

  - usb: chipidea: Grab the (legacy) USB PHY by phandle
    first (bnc#1012382).

  - usb: Consolidate LPM checks to avoid enabling LPM twice
    (bsc#1129770).

  - usb: core: only clean up what we allocated
    (bnc#1012382).

  - usb: dwc2: Fix DMA alignment to start at allocated
    boundary (bsc#1100132).

  - usb: dwc2: fix the incorrect bitmaps for the ports of
    multi_tt hub (bsc#1100132).

  - usb: dwc3: gadget: Fix suspend/resume during device mode
    (bnc#1012382).

  - usb: dwc3: gadget: Fix the uninitialized link_state when
    udc starts (bnc#1012382).

  - usb: gadget: Add the gserial port checking in
    gs_start_tx() (bnc#1012382).

  - usb: gadget: composite: fix dereference after null check
    coverify warning (bnc#1012382).

  - usb: gadget: configfs: add mutex lock before unregister
    gadget (bnc#1012382).

  - usb: gadget: Potential NULL dereference on allocation
    error (bnc#1012382).

  - usb: gadget: rndis: free response queue during
    REMOTE_NDIS_RESET_MSG (bnc#1012382).

  - usb: renesas_usbhs: gadget: fix unused-but-set-variable
    warning (bnc#1012382).

  - usb: serial: cp210x: add ID for Ingenico 3070
    (bnc#1012382).

  - usb: serial: cp210x: add new device id (bnc#1012382).

  - usb: serial: cypress_m8: fix interrupt-out transfer
    length (bsc#1119086).

  - usb: serial: ftdi_sio: add additional NovaTech products
    (bnc#1012382).

  - usb: serial: ftdi_sio: add ID for Hjelmslund Electronics
    USB485 (bnc#1012382).

  - usb: serial: mos7720: fix mos_parport refcount imbalance
    on error path (bsc#1129770).

  - usb: serial: option: add Olicard 600 (bnc#1012382).

  - usb: serial: option: add Telit ME910 ECM composition
    (bnc#1012382).

  - usb: serial: option: set driver_info for SIM5218 and
    compatibles (bsc#1129770).

  - video: fbdev: Set pixclock = 0 in goldfishfb
    (bnc#1012382).

  - vti4: Fix a ipip packet processing bug in 'IPCOMP'
    virtual tunnel (bnc#1012382).

  - vxlan: Do not call gro_cells_destroy() before device is
    unregistered (bnc#1012382).

  - vxlan: Fix GRO cells race condition between receive and
    link delete (bnc#1012382).

  - vxlan: test dev->flags & IFF_UP before calling
    gro_cells_receive() (bnc#1012382).

  - wlcore: Fix memory leak in case wl12xx_fetch_firmware
    failure (bnc#1012382).

  - wlcore: Fix the return value in case of error in
    'wlcore_vendor_cmd_smart_config_start()' (bsc#1120902).

  - x.509: unpack RSA signatureValue field from BIT STRING
    (git-fixes).

  - x86_64: increase stack size for KASAN_EXTRA
    (bnc#1012382).

  - x86/apic: Provide apic_ack_irq() (bsc#1122822).

  - x86/apic: Provide apic_ack_irq() (fate#327171,
    bsc#1122822).

  - x86/build: Mark per-CPU symbols as absolute explicitly
    for LLD (bnc#1012382).

  - x86/build: Specify elf_i386 linker emulation explicitly
    for i386 objects (bnc#1012382).

  - x86/CPU/AMD: Set the CPB bit unconditionally on F17h
    (bnc#1012382).

  - x86/cpu/cyrix: Use correct macros for Cyrix calls on
    Geode processors (bnc#1012382).

  - x86/hpet: Prevent potential NULL pointer dereference
    (bnc#1012382).

  - x86/hw_breakpoints: Make default case in
    hw_breakpoint_arch_parse() return an error
    (bnc#1012382).

  - x86/Hyper-V: Set x2apic destination mode to physical
    when x2apic is available (bsc#1122822).

  - x86/Hyper-V: Set x2apic destination mode to physical
    when x2apic is available (fate#327171, bsc#1122822).

  - x86/kexec: Do not setup EFI info if EFI runtime is not
    enabled (bnc#1012382).

  - x86/kprobes: Verify stack frame on kretprobe
    (bnc#1012382).

  - x86/mce: Improve error message when kernel cannot
    recover, p2 (bsc#1114648).

  - x86/smp: Enforce CONFIG_HOTPLUG_CPU when SMP=y
    (bnc#1012382).

  - x86/speculation: Remove redundant arch_smt_update()
    invocation (bsc#1111331).

  - x86/speculation: Support 'mitigations=' cmdline option
    (bsc#1112178).

  - x86/uaccess: Do not leak the AC flag into __put_user()
    value evaluation (bsc#1114648).

  - x86/vdso: Add VCLOCK_HVCLOCK vDSO clock read method
    (bsc#1133308).

  - x86/vdso: Drop implicit common-page-size linker flag
    (bnc#1012382).

  - x86/vdso: Pass --eh-frame-hdr to the linker (git-fixes).

  - x86: vdso: Use $LD instead of $CC to link (bnc#1012382).

  - xen-netback: fix occasional leak of grant ref mappings
    under memory pressure (bnc#1012382).

  - xen: Prevent buffer overflow in privcmd ioctl
    (bnc#1012382).

  - xfrm_user: fix info leak in build_aevent() (git-fixes).

  - xfrm_user: fix info leak in xfrm_notify_sa()
    (git-fixes).

  - xhci: Do not let USB3 ports stuck in polling state
    prevent suspend (bsc#1047487).

  - xhci: Fix port resume done detection for SS ports with
    LPM enabled (bnc#1012382).

  - xtensa: fix return_address (bnc#1012382).

  - xtensa: SMP: fix ccount_timer_shutdown (bnc#1012382).

  - xtensa: SMP: fix secondary CPU initialization
    (bnc#1012382).

  - xtensa: SMP: limit number of possible CPUs by NR_CPUS
    (bnc#1012382).

  - xtensa: SMP: mark each possible CPU as present
    (bnc#1012382).

  - xtensa: smp_lx200_defconfig: fix vectors clash
    (bnc#1012382)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047487"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=843419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/support/kb/doc/?id=7023736"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/21");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.179-99.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.179-99.1") ) flag++;

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
