#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1404.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(125243);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/17  9:44:15");

  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-16880", "CVE-2019-11091", "CVE-2019-11486", "CVE-2019-11815", "CVE-2019-11884", "CVE-2019-3882", "CVE-2019-9003", "CVE-2019-9500", "CVE-2019-9503");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-1404) (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)");
  script_summary(english:"Check for the openSUSE-2019-1404 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 15.0 kernel was updated to receive various security
and bugfixes.

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

  - CVE-2018-16880: A flaw was found in handle_rx() function
    in the vhost_net driver. A malicious virtual guest,
    under specific conditions, can trigger an out-of-bounds
    write in a kmalloc-8 slab on a virtual host which may
    lead to a kernel memory corruption and a system panic.
    Due to the nature of the flaw, privilege escalation
    cannot be fully ruled out. (bnc#1122767).

  - CVE-2019-11486: The Siemens R3964 line discipline driver
    in drivers/tty/n_r3964.c had multiple race conditions
    (bnc#1133188). It has been disabled.

  - CVE-2019-11815: An issue was discovered in
    rds_tcp_kill_sock in net/rds/tcp.c. There is a race
    condition leading to a use-after-free, related to net
    namespace cleanup (bnc#1134537).

  - CVE-2019-11884: The do_hidp_sock_ioctl function in
    net/bluetooth/hidp/sock.c allowed a local user to obtain
    potentially sensitive information from kernel stack
    memory via a HIDPCONNADD command, because a name field
    may not end with a '\0' character (bnc#1134848).

  - CVE-2019-3882: A flaw was found in vfio interface
    implementation that permits violation of the user's
    locked memory limit. If a device is bound to a vfio
    driver, such as vfio-pci, and the local attacker is
    administratively granted ownership of the device, it may
    cause a system memory exhaustion and thus a denial of
    service (DoS). (bnc#1131416 bnc#1131427).

  - CVE-2019-9003: Attackers can trigger a
    drivers/char/ipmi/ipmi_msghandler.c use-after-free and
    OOPS by arranging for certain simultaneous execution of
    the code, as demonstrated by a 'service ipmievd restart'
    loop (bnc#1126704).

  - CVE-2019-9500: A brcmfmac heap buffer overflow in
    brcmf_wowl_nd_results was fixed (bnc#1132681).

  - CVE-2019-9503: Multiple brcmfmac frame validation
    bypasses have been fixed (bnc#1132828).

The following non-security bugs were fixed :

  - 9p: do not trust pdu content for stat item size
    (bsc#1051510).

  - acpi, nfit: Prefer _DSM over _LSR for namespace label
    reads (bsc#1112128) (bsc#1132426).

  - ACPI / SBS: Fix GPE storm on recent MacBookPro's
    (bsc#1051510).

  - ALSA: core: Do not refer to snd_cards array directly
    (bsc#1051510).

  - ALSA: core: Fix card races between register and
    disconnect (bsc#1051510).

  - ALSA: emu10k1: Drop superfluous id-uniquification
    behavior (bsc#1051510).

  - ALSA: hda - Add two more machines to the
    power_save_blacklist (bsc#1051510).

  - ALSA: hda/hdmi - Consider eld_valid when reporting jack
    event (bsc#1051510).

  - ALSA: hda/hdmi - Read the pin sense from register when
    repolling (bsc#1051510).

  - ALSA: hda: Initialize power_state field properly
    (bsc#1051510).

  - ALSA: hda/realtek - Add new Dell platform for headset
    mode (bsc#1051510).

  - ALSA: hda/realtek - Add quirk for Tuxedo XC 1509
    (bsc#1131442).

  - ALSA: hda/realtek - Add support headset mode for DELL
    WYSE AIO (bsc#1051510).

  - ALSA: hda/realtek - Add support headset mode for New
    DELL WYSE NB (bsc#1051510).

  - ALSA: hda/realtek - add two more pin configuration sets
    to quirk table (bsc#1051510).

  - ALSA: hda/realtek - Apply the fixup for ASUS Q325UAR
    (bsc#1051510).

  - ALSA: hda/realtek - EAPD turn on later (bsc#1051510).

  - ALSA: hda/realtek - Fixed Dell AIO speaker noise
    (bsc#1051510).

  - ALSA: hda - Register irq handler after the chip
    initialization (bsc#1051510).

  - ALSA: hdea/realtek - Headset fixup for System76 Gazelle
    (gaze14) (bsc#1051510).

  - ALSA: info: Fix racy addition/deletion of nodes
    (bsc#1051510).

  - ALSA: line6: Avoid polluting led_* namespace
    (bsc#1051510).

  - ALSA: line6: use dynamic buffers (bsc#1051510).

  - ALSA: PCM: check if ops are defined before suspending
    PCM (bsc#1051510).

  - ALSA: seq: Align temporary re-locking with irqsave
    version (bsc#1051510).

  - ALSA: seq: Correct unlock sequence at
    snd_seq_client_ioctl_unlock() (bsc#1051510).

  - ALSA: seq: Cover unsubscribe_port() in list_mutex
    (bsc#1051510).

  - ALSA: seq: Fix OOB-reads from strlcpy (bsc#1051510).

  - ALSA: seq: Fix race of get-subscription call vs
    port-delete ioctls (bsc#1051510).

  - ALSA: seq: Protect in-kernel ioctl calls with mutex
    (bsc#1051510).

  - ALSA: seq: Protect racy pool manipulation from OSS
    sequencer (bsc#1051510).

  - ALSA: seq: Remove superfluous irqsave flags
    (bsc#1051510).

  - ALSA: seq: Simplify snd_seq_kernel_client_enqueue()
    helper (bsc#1051510).

  - ALSA: timer: Check ack_list emptiness instead of bit
    flag (bsc#1051510).

  - ALSA: timer: Coding style fixes (bsc#1051510).

  - ALSA: timer: Make snd_timer_close() really kill pending
    actions (bsc#1051510).

  - ALSA: timer: Make sure to clear pending ack list
    (bsc#1051510).

  - ALSA: timer: Revert active callback sync check at close
    (bsc#1051510).

  - ALSA: timer: Simplify error path in snd_timer_open()
    (bsc#1051510).

  - ALSA: timer: Unify timer callback process code
    (bsc#1051510).

  - ALSA: usb-audio: Fix a memory leak bug (bsc#1051510).

  - ALSA: usb-audio: Handle the error from
    snd_usb_mixer_apply_create_quirk() (bsc#1051510).

  - ALSA: usx2y: fix a double free bug (bsc#1051510).

  - ASoC: cs4270: Set auto-increment bit for register writes
    (bsc#1051510).

  - ASoC: fix valid stream condition (bsc#1051510).

  - ASoC: fsl-asoc-card: fix object reference leaks in
    fsl_asoc_card_probe (bsc#1051510).

  - ASoC: fsl_esai: fix channel swap issue when stream
    starts (bsc#1051510).

  - ASoC: fsl_esai: Fix missing break in switch statement
    (bsc#1051510).

  - ASoC: hdmi-codec: fix S/PDIF DAI (bsc#1051510).

  - ASoC: Intel: avoid Oops if DMA setup fails
    (bsc#1051510).

  - ASoC: max98090: Fix restore of DAPM Muxes (bsc#1051510).

  - ASoC: nau8810: fix the issue of widget with prefixed
    name (bsc#1051510).

  - ASoC: nau8824: fix the issue of the widget with prefix
    name (bsc#1051510).

  - ASoC: RT5677-SPI: Disable 16Bit SPI Transfers
    (bsc#1051510).

  - ASoC: samsung: odroid: Fix clock configuration for 44100
    sample rate (bsc#1051510).

  - ASoC:soc-pcm:fix a codec fixup issue in TDM case
    (bsc#1051510).

  - ASoC: stm32: fix sai driver name initialisation
    (bsc#1051510).

  - ASoC: tlv320aic32x4: Fix Common Pins (bsc#1051510).

  - ASoC: topology: free created components in tplg load
    error (bsc#1051510).

  - ASoC: wm_adsp: Add locking to wm_adsp2_bus_error
    (bsc#1051510).

  - assume flash part size to be 4MB, if it can't be
    determined (bsc#1127371).

  - at76c50x-usb: Do not register led_trigger if
    usb_register_driver failed (bsc#1051510).

  - ath10k: avoid possible string overflow (bsc#1051510).

  - audit: fix a memleak caused by auditing load module
    (bsc#1051510).

  - b43: shut up clang -Wuninitialized variable warning
    (bsc#1051510).

  - batman-adv: Reduce claim hash refcnt only for removed
    entry (bsc#1051510).

  - batman-adv: Reduce tt_global hash refcnt only for
    removed entry (bsc#1051510).

  - batman-adv: Reduce tt_local hash refcnt only for removed
    entry (bsc#1051510).

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

  - bcache: correct dirty data statistics (bsc#1130972).

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

  - bcache: fix input overflow to cache set io_error_limit
    (bsc#1130972).

  - bcache: fix input overflow to cache set sysfs file
    io_error_halflife (bsc#1130972).

  - bcache: fix input overflow to journal_delay_ms
    (bsc#1130972).

  - bcache: fix input overflow to sequential_cutoff
    (bsc#1130972).

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

  - bcache: improve sysfs_strtoul_clamp() (bsc#1130972).

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

  - bcache: Replace bch_read_string_list() by
    __sysfs_match_string() (bsc#1130972).

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

  - bcache: stop bcache device when backing device is
    offline (bsc#1130972).

  - bcache: stop using the deprecated get_seconds()
    (bsc#1130972).

  - bcache: style fixes for lines over 80 characters
    (bsc#1130972).

  - bcache: style fix to add a blank line after declarations
    (bsc#1130972).

  - bcache: style fix to replace 'unsigned' by 'unsigned
    int' (bsc#1130972).

  - bcache: treat stale && dirty keys as bad keys
    (bsc#1130972).

  - bcache: trivial - remove tailing backslash in macro
    BTREE_FLAG (bsc#1130972).

  - bcache: update comment for bch_data_insert
    (bsc#1130972).

  - bcache: update comment in sysfs.c (bsc#1130972).

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

  - blkcg: Introduce blkg_root_lookup() (bsc#1131673).

  - blkcg: Make blkg_root_lookup() work for queues in bypass
    mode (bsc#1131673).

  - blk-mq: adjust debugfs and sysfs register when updating
    nr_hw_queues (bsc#1131673).

  - blk-mq: Avoid that submitting a bio concurrently with
    device removal triggers a crash (bsc#1131673).

  - blk-mq: change gfp flags to GFP_NOIO in
    blk_mq_realloc_hw_ctxs (bsc#1131673).

  - blk-mq: fallback to previous nr_hw_queues when updating
    fails (bsc#1131673).

  - blk-mq: init hctx sched after update ctx and hctx
    mapping (bsc#1131673).

  - blk-mq: realloc hctx when hw queue is mapped to another
    node (bsc#1131673).

  - blk-mq: sync the update nr_hw_queues with
    blk_mq_queue_tag_busy_iter (bsc#1131673).

  - block: check_events: do not bother with events if
    unsupported (bsc#1110946, bsc#1119843).

  - block: disk_events: introduce event flags (bsc#1110946,
    bsc#1119843).

  - block: Ensure that a request queue is dissociated from
    the cgroup controller (bsc#1131673).

  - block: Fix a race between request queue removal and the
    block cgroup controller (bsc#1131673).

  - block: Introduce blk_exit_queue() (bsc#1131673).

  - block: kABI fixes for bio_rewind_iter() removal
    (bsc#1131673).

  - block: remove bio_rewind_iter() (bsc#1131673).

  - bluetooth: Align minimum encryption key size for LE and
    BR/EDR connections (bsc#1051510).

  - bluetooth: btusb: request wake pin with NOAUTOEN
    (bsc#1051510).

  - bluetooth: Check L2CAP option sizes returned from
    l2cap_get_conf_opt (bsc#1051510).

  - bluetooth: hci_uart: Check if socket buffer is ERR_PTR
    in h4_recv_buf() (bsc#1133731).

  - bluetooth: hidp: fix buffer overflow (bsc#1051510).

  - bnxt_en: Drop oversize TX packets to prevent errors
    (networking-stable-19_03_07).

  - bonding: fix PACKET_ORIGDEV regression (git-fixes).

  - bpf: fix use after free in bpf_evict_inode
    (bsc#1083647).

  - brcm80211: potential NULL dereference in
    brcmf_cfg80211_vndr_cmds_dcmd_handler() (bsc#1051510).

  - btrfs: add a helper to return a head ref (bsc#1134813).

  - btrfs: Avoid possible qgroup_rsv_size overflow in
    btrfs_calculate_inode_block_rsv_size (git-fixes).

  - btrfs: breakout empty head cleanup to a helper
    (bsc#1134813).

  - btrfs: check for refs on snapshot delete resume
    (bsc#1131335).

  - btrfs: delayed-ref: Introduce better documented delayed
    ref structures (bsc#1063638 bsc#1128052 bsc#1108838).

  - btrfs: Do not panic when we can't find a root key
    (bsc#1112063).

  - btrfs: extent-tree: Open-code process_func in
    __btrfs_mod_ref (bsc#1063638 bsc#1128052 bsc#1108838).

  - btrfs: Factor out common delayed refs init code
    (bsc#1134813).

  - btrfs: fix assertion failure on fsync with NO_HOLES
    enabled (bsc#1131848).

  - btrfs: Fix bound checking in
    qgroup_trace_new_subtree_blocks (git-fixes).

  - btrfs: fix incorrect file size after shrinking truncate
    and fsync (bsc#1130195).

  - btrfs: Introduce init_delayed_ref_head (bsc#1134813).

  - btrfs: move all ref head cleanup to the helper function
    (bsc#1134813).

  - btrfs: move extent_op cleanup to a helper (bsc#1134813).

  - btrfs: move ref_mod modification into the if (ref) logic
    (bsc#1134813).

  - btrfs: Open-code add_delayed_data_ref (bsc#1134813).

  - btrfs: Open-code add_delayed_tree_ref (bsc#1134813).

  - btrfs: qgroup: Move reserved data accounting from
    btrfs_delayed_ref_head to btrfs_qgroup_extent_record
    (bsc#1134162).

  - btrfs: qgroup: Remove duplicated trace points for
    qgroup_rsv_add/release (bsc#1134160).

  - btrfs: remove delayed_ref_node from ref_head
    (bsc#1134813).

  - btrfs: remove WARN_ON in log_dir_items (bsc#1131847).

  - btrfs: save drop_progress if we drop refs at all
    (bsc#1131336).

  - btrfs: split delayed ref head initialization and
    addition (bsc#1134813).

  - btrfs: track refs in a rb_tree instead of a list
    (bsc#1134813).

  - btrfs: Use init_delayed_ref_common in
    add_delayed_data_ref (bsc#1134813).

  - btrfs: Use init_delayed_ref_common in
    add_delayed_tree_ref (bsc#1134813).

  - btrfs: Use init_delayed_ref_head in add_delayed_ref_head
    (bsc#1134813).

  - cdrom: Fix race condition in cdrom_sysctl_register
    (bsc#1051510).

  - ceph: ensure d_name stability in ceph_dentry_hash()
    (bsc#1134461).

  - ceph: fix ci->i_head_snapc leak (bsc#1122776).

  - ceph: fix use-after-free on symlink traversal
    (bsc#1134459).

  - ceph: only use d_name directly when parent is locked
    (bsc#1134460).

  - cgroup: fix parsing empty mount option string
    (bsc#1133094).

  - cifs: Do not count -ENODATA as failure for query
    directory (bsc#1051510).

  - cifs: do not dereference smb_file_target before null
    check (bsc#1051510).

  - cifs: Do not hide EINTR after sending network packets
    (bsc#1051510).

  - cifs: Do not reconnect TCP session in add_credits()
    (bsc#1051510).

  - cifs: Do not reset lease state to NONE on lease break
    (bsc#1051510).

  - cifs: Fix adjustment of credits for MTU requests
    (bsc#1051510).

  - cifs: Fix credit calculation for encrypted reads with
    errors (bsc#1051510).

  - cifs: Fix credits calculations for reads with errors
    (bsc#1051510).

  - cifs: fix POSIX lock leak and invalid ptr deref
    (bsc#1114542).

  - cifs: Fix possible hang during async MTU reads and
    writes (bsc#1051510).

  - cifs: Fix potential OOB access of lock element array
    (bsc#1051510).

  - cifs: Fix read after write for files with read caching
    (bsc#1051510).

  - clk: fractional-divider: check parent rate only if flag
    is set (bsc#1051510).

  - clk: rockchip: fix frac settings of GPLL clock for
    rk3328 (bsc#1051510).

  - clk: rockchip: Fix video codec clocks on rk3288
    (bsc#1051510).

  - clk: rockchip: fix wrong clock definitions for rk3328
    (bsc#1051510).

  - clk: x86: Add system specific quirk to mark clocks as
    critical (bsc#1051510).

  - cpupowerutils: bench - Fix cpu online check
    (bsc#1051510).

  - cpu/speculation: Add 'mitigations=' cmdline option
    (bsc#1112178).

  - crypto: arm/aes-neonbs - do not access already-freed
    walk.iv (bsc#1051510).

  - crypto: caam - add missing put_device() call
    (bsc#1129770).

  - crypto: ccm - fix incompatibility between 'ccm' and
    'ccm_base' (bsc#1051510).

  - crypto: ccp - Do not free psp_master when PLATFORM_INIT
    fails (bsc#1051510).

  - crypto: chacha20poly1305 - set cra_name correctly
    (bsc#1051510).

  - crypto: crct10dif-generic - fix use via
    crypto_shash_digest() (bsc#1051510).

  - crypto: crypto4xx - properly set IV after de- and
    encrypt (bsc#1051510).

  - crypto: fips - Grammar s/options/option/, s/to/the/
    (bsc#1051510).

  - crypto: gcm - fix incompatibility between 'gcm' and
    'gcm_base' (bsc#1051510).

  - crypto: pcbc - remove bogus memcpy()s with src == dest
    (bsc#1051510).

  - crypto: sha256/arm - fix crash bug in Thumb2 build
    (bsc#1051510).

  - crypto: sha512/arm - fix crash bug in Thumb2 build
    (bsc#1051510).

  - crypto: skcipher - do not WARN on unprocessed data after
    slow walk step (bsc#1051510).

  - crypto: sun4i-ss - Fix invalid calculation of hash end
    (bsc#1051510).

  - crypto: vmx - fix copy-paste error in CTR mode
    (bsc#1051510).

  - crypto: x86/crct10dif-pcl - fix use via
    crypto_shash_digest() (bsc#1051510).

  - crypto: x86/poly1305 - fix overflow during partial
    reduction (bsc#1051510).

  - cxgb4: Add capability to get/set SGE Doorbell Queue
    Timer Tick (bsc#1127371).

  - cxgb4: Added missing break in ndo_udp_tunnel_{add/del}
    (bsc#1127371).

  - cxgb4: Add flag tc_flower_initialized (bsc#1127371).

  - cxgb4: Add new T5 PCI device id 0x50ae (bsc#1127371).

  - cxgb4: Add new T5 PCI device ids 0x50af and 0x50b0
    (bsc#1127371).

  - cxgb4: Add new T6 PCI device ids 0x608a (bsc#1127371).

  - cxgb4: add per rx-queue counter for packet errors
    (bsc#1127371).

  - cxgb4: Add support for FW_ETH_TX_PKT_VM_WR
    (bsc#1127371).

  - cxgb4: add support to display DCB info (bsc#1127371).

  - cxgb4: Add support to read actual provisioned resources
    (bsc#1127371).

  - cxgb4: collect ASIC LA dumps from ULP TX (bsc#1127371).

  - cxgb4: collect hardware queue descriptors (bsc#1127371).

  - cxgb4: collect number of free PSTRUCT page pointers
    (bsc#1127371).

  - cxgb4: convert flower table to use rhashtable
    (bsc#1127371).

  - cxgb4: cxgb4: use FW_PORT_ACTION_L1_CFG32 for 32 bit
    capability (bsc#1127371).

  - cxgb4/cxgb4vf: Add support for SGE doorbell queue timer
    (bsc#1127371).

  - cxgb4/cxgb4vf: Fix mac_hlist initialization and free
    (bsc#1127374).

  - cxgb4/cxgb4vf: Link management changes (bsc#1127371).

  - cxgb4/cxgb4vf: Program hash region for
    {t4/t4vf}_change_mac() (bsc#1127371).

  - cxgb4: display number of rx and tx pages free
    (bsc#1127371).

  - cxgb4: do not return DUPLEX_UNKNOWN when link is down
    (bsc#1127371).

  - cxgb4: Export sge_host_page_size to ulds (bsc#1127371).

  - cxgb4: fix the error path of cxgb4_uld_register()
    (bsc#1127371).

  - cxgb4: impose mandatory VLAN usage when non-zero TAG ID
    (bsc#1127371).

  - cxgb4: Mask out interrupts that are not enabled
    (bsc#1127175).

  - cxgb4: move Tx/Rx free pages collection to common code
    (bsc#1127371).

  - cxgb4: remove redundant assignment to
    vlan_cmd.dropnovlan_fm (bsc#1127371).

  - cxgb4: Remove SGE_HOST_PAGE_SIZE dependency on page size
    (bsc#1127371).

  - cxgb4: remove the unneeded locks (bsc#1127371).

  - cxgb4: specify IQTYPE in fw_iq_cmd (bsc#1127371).

  - cxgb4: Support ethtool private flags (bsc#1127371).

  - cxgb4: update supported DCB version (bsc#1127371).

  - cxgb4: use new fw interface to get the VIN and smt index
    (bsc#1127371).

  - cxgb4vf: Few more link management changes (bsc#1127374).

  - cxgb4vf: fix memleak in mac_hlist initialization
    (bsc#1127374).

  - cxgb4vf: Update port information in cxgb4vf_open()
    (bsc#1127374).

  - device_cgroup: fix RCU imbalance in error case
    (bsc#1051510).

  - Disable kgdboc failed by echo space to
    /sys/module/kgdboc/parameters/kgdboc (bsc#1051510).

  - dmaengine: axi-dmac: Do not check the number of frames
    for alignment (bsc#1051510).

  - dmaengine: imx-dma: fix warning comparison of distinct
    pointer types (bsc#1051510).

  - dmaengine: qcom_hidma: assign channel cookie correctly
    (bsc#1051510).

  - dmaengine: sh: rcar-dmac: With cyclic DMA residue 0 is
    valid (bsc#1051510).

  - dmaengine: tegra210-dma: free dma controller in remove()
    (bsc#1051510).

  - dmaengine: tegra: avoid overflow of byte tracking
    (bsc#1051510).

  - dm: disable DISCARD if the underlying storage no longer
    supports it (bsc#1114638).

  - drivers: hv: vmbus: Offload the handling of channels to
    two workqueues (bsc#1130567).

  - drivers: hv: vmbus: Reset the channel callback in
    vmbus_onoffer_rescind() (bsc#1130567).

  - drm: Auto-set allow_fb_modifiers when given modifiers at
    plane init (bsc#1051510).

  - drm: bridge: dw-hdmi: Fix overflow workaround for
    Rockchip SoCs (bsc#1113722)

  - drm/dp/mst: Configure no_stop_bit correctly for remote
    i2c xfers (bsc#1051510).

  - drm/fb-helper: dpms_legacy(): Only set on connectors in
    use (bsc#1051510).

  - drm/i915: Fix I915_EXEC_RING_MASK (bsc#1051510).

  - drm/i915/gvt: Add in context mmio 0x20D8 to gen9 mmio
    list (bsc#1113722)

  - drm/i915/gvt: Annotate iomem usage (bsc#1051510).

  - drm/i915/gvt: do not deliver a workload if its creation
    fails (bsc#1051510).

  - drm/i915/gvt: do not let pin count of shadow mm go
    negative (bsc#1113722)

  - drm/i915/gvt: Fix incorrect mask of mmio 0x22028 in
    gen8/9 mmio list (bnc#1113722)

  - drm/i915/gvt: Fix MI_FLUSH_DW parsing with correct index
    check (bsc#1051510).

  - drm/mediatek: Fix an error code in
    mtk_hdmi_dt_parse_pdata() (bsc#1113722)

  - drm/mediatek: fix possible object reference leak
    (bsc#1051510).

  - drm/meson: add size and alignment requirements for dumb
    buffers (bnc#1113722)

  - drm/meson: Fix invalid pointer in meson_drv_unbind()
    (bsc#1051510).

  - drm/meson: Uninstall IRQ handler (bsc#1051510).

  - drm/nouveau: Stop using drm_crtc_force_disable
    (bsc#1051510).

  - drm/nouveau/volt/gf117: fix speedo readout register
    (bsc#1051510).

  - drm/rockchip: shutdown drm subsystem on shutdown
    (bsc#1051510).

  - drm/rockchip: vop: reset scale mode when win is disabled
    (bsc#1113722)

  - drm/sun4i: Add missing drm_atomic_helper_shutdown at
    driver unbind (bsc#1113722)

  - drm/sun4i: Fix component unbinding and component master
    deletion (bsc#1113722)

  - drm/sun4i: rgb: Change the pixel clock validation check
    (bnc#1113722)

  - drm/sun4i: Set device driver data at bind time for use
    in unbind (bsc#1113722)

  - drm/sun4i: Unbind components before releasing DRM and
    memory (bsc#1113722)

  - drm/ttm: Remove warning about inconsistent mapping
    information (bnc#1131488)

  - drm/udl: add a release method and delay modeset teardown
    (bsc#1085536)

  - drm/vc4: Fix memory leak during gpu reset. (bsc#1113722)

  - dsa: mv88e6xxx: Ensure all pending interrupts are
    handled prior to exit (networking-stable-19_02_20).

  - dt-bindings: net: Fix a typo in the phy-mode list for
    ethernet bindings (bsc#1129770).

  - dwc2: gadget: Fix completed transfer size calculation in
    DDMA (bsc#1051510).

  - e1000e: fix cyclic resets at link up with active tx
    (bsc#1051510).

  - e1000e: Fix -Wformat-truncation warnings (bsc#1051510).

  - ext2: Fix underflow in ext2_max_size() (bsc#1131174).

  - ext4: add mask of ext4 flags to swap (bsc#1131170).

  - ext4: add missing brelse() in add_new_gdb_meta_bg()
    (bsc#1131176).

  - ext4: brelse all indirect buffer in
    ext4_ind_remove_space() (bsc#1131173).

  - ext4: cleanup bh release code in ext4_ind_remove_space()
    (bsc#1131851).

  - ext4: cleanup pagecache before swap i_data
    (bsc#1131178).

  - ext4: fix check of inode in swap_inode_boot_loader
    (bsc#1131177).

  - ext4: fix data corruption caused by unaligned direct AIO
    (bsc#1131172).

  - ext4: fix EXT4_IOC_SWAP_BOOT (bsc#1131180).

  - ext4: fix NULL pointer dereference while journal is
    aborted (bsc#1131171).

  - ext4: update quota information while swapping boot
    loader inode (bsc#1131179).

  - fbdev: fbmem: fix memory access if logo is bigger than
    the screen (bsc#1051510).

  - fix cgroup_do_mount() handling of failure exits
    (bsc#1133095).

  - Fix kabi after 'md: batch flush requests.'
    (bsc#1119680).

  - Fix struct page kABI after adding atomic for ppc
    (bsc#1131326, bsc#1108937).

  - fm10k: Fix a potential NULL pointer dereference
    (bsc#1051510).

  - fs: avoid fdput() after failed fdget() in
    vfs_dedupe_file_range() (bsc#1132384, bsc#1132219).

  - fs/nfs: Fix nfs_parse_devname to not modify it's
    argument (git-fixes).

  - futex: Cure exit race (bsc#1050549).

  - futex: Ensure that futex address is aligned in
    handle_futex_death() (bsc#1050549).

  - futex: Handle early deadlock return correctly
    (bsc#1050549).

  - ghes, EDAC: Fix ghes_edac registration (bsc#1133176).

  - gpio: adnp: Fix testing wrong value in
    adnp_gpio_direction_input (bsc#1051510).

  - gpio: aspeed: fix a potential NULL pointer dereference
    (bsc#1051510).

  - gpio: gpio-omap: fix level interrupt idling
    (bsc#1051510).

  - gpio: of: Fix of_gpiochip_add() error path
    (bsc#1051510).

  - gre6: use log_ecn_error module parameter in
    ip6_tnl_rcv() (git-fixes).

  - hid: debug: fix race condition with between rdesc_show()
    and device removal (bsc#1051510).

  - hid: i2c-hid: Ignore input report if there's no data
    present on Elan touchpanels (bsc#1133486).

  - hid: input: add mapping for Assistant key (bsc#1051510).

  - hid: intel-ish-hid: avoid binding wrong ishtp_cl_device
    (bsc#1051510).

  - hid: intel-ish: ipc: handle PIMR before ish_wakeup also
    clear PISR busy_clear bit (bsc#1051510).

  - hid: logitech: check the return value of
    create_singlethread_workqueue (bsc#1051510).

  - hv_netvsc: Fix IP header checksum for coalesced packets
    (networking-stable-19_03_07).

  - hwmon: (f71805f) Use request_muxed_region for Super-IO
    accesses (bsc#1051510).

  - hwmon: (pc87427) Use request_muxed_region for Super-IO
    accesses (bsc#1051510).

  - hwmon: (smsc47b397) Use request_muxed_region for
    Super-IO accesses (bsc#1051510).

  - hwmon: (smsc47m1) Use request_muxed_region for Super-IO
    accesses (bsc#1051510).

  - hwmon: (vt1211) Use request_muxed_region for Super-IO
    accesses (bsc#1051510).

  - hwmon: (w83627hf) Use request_muxed_region for Super-IO
    accesses (bsc#1051510).

  - hwrng: virtio - Avoid repeated init of completion
    (bsc#1051510).

  - i2c: Make i2c_unregister_device() NULL-aware
    (bsc#1108193).

  - ibmvnic: Enable GRO (bsc#1132227).

  - ibmvnic: Fix completion structure initialization
    (bsc#1131659).

  - ibmvnic: Fix netdev feature clobbering during a reset
    (bsc#1132227).

  - iio: adc: at91: disable adc channel interrupt in timeout
    case (bsc#1051510).

  - iio: adc: fix warning in Qualcomm PM8xxx HK/XOADC driver
    (bsc#1051510).

  - iio: ad_sigma_delta: select channel when reading
    register (bsc#1051510).

  - iio: core: fix a possible circular locking dependency
    (bsc#1051510).

  - iio: cros_ec: Fix the maths for gyro scale calculation
    (bsc#1051510).

  - iio: dac: mcp4725: add missing powerdown bits in store
    eeprom (bsc#1051510).

  - iio: Fix scan mask selection (bsc#1051510).

  - iio/gyro/bmg160: Use millidegrees for temperature scale
    (bsc#1051510).

  - iio: gyro: mpu3050: fix chip ID reading (bsc#1051510).

  - Input: introduce KEY_ASSISTANT (bsc#1051510).

  - Input: snvs_pwrkey - initialize necessary driver data
    before enabling IRQ (bsc#1051510).

  - Input: synaptics-rmi4 - write config register values to
    the right offset (bsc#1051510).

  - intel_idle: add support for Jacobsville (jsc#SLE-5394).

  - intel_th: msu: Fix single mode with IOMMU (bsc#1051510).

  - intel_th: pci: Add Comet Lake support (bsc#1051510).

  - io: accel: kxcjk1013: restore the range after resume
    (bsc#1051510).

  - iommu/amd: Set exclusion range correctly (bsc#1130425).

  - iommu/vt-d: Do not request page request irq under
    dmar_global_lock (bsc#1135006).

  - iommu/vt-d: Make kernel parameter igfx_off work with
    vIOMMU (bsc#1135007).

  - iommu/vt-d: Set intel_iommu_gfx_mapped correctly
    (bsc#1135008).

  - ip6_tunnel: fix ip6 tunnel lookup in collect_md mode
    (git-fixes).

  - ipmi: Fix I2C client removal in the SSIF driver
    (bsc#1108193).

  - ipmi:ssif: compare block number correctly for multi-part
    return messages (bsc#1051510).

  - ipmi_ssif: Remove duplicate NULL check (bsc#1108193).

  - ipv4: Return error for RTA_VIA attribute
    (networking-stable-19_03_07).

  - ipv6: Fix dangling pointer when ipv6 fragment
    (git-fixes).

  - ipv6: propagate genlmsg_reply return code
    (networking-stable-19_02_24).

  - ipv6: Return error for RTA_VIA attribute
    (networking-stable-19_03_07).

  - ipv6: sit: reset ip header pointer in ipip6_rcv
    (git-fixes).

  - ipvlan: disallow userns cap_net_admin to change global
    mode/flags (networking-stable-19_03_15).

  - ipvs: remove IPS_NAT_MASK check to fix passive FTP
    (git-fixes).

  - It's wrong to add len to sector_nr in raid10 reshape
    twice (git-fixes).

  - iw_cxgb4: cq/qp mask depends on bar2 pages in a host
    page (bsc#1127371).

  - iwiwifi: fix bad monitor buffer register addresses
    (bsc#1129770).

  - iwlwifi: fix send hcmd timeout recovery flow
    (bsc#1129770).

  - jbd2: clear dirty flag when revoking a buffer from an
    older transaction (bsc#1131167).

  - jbd2: fix compile warning when using JBUFFER_TRACE
    (bsc#1131168).

  - kABI: restore icmp_send (kabi).

  - kabi/severities: add cxgb4 and cxgb4vf shared data to
    the whitelis (bsc#1127372)

  - kABI workaround for removed usb_interface.pm_usage_cnt
    field (bsc#1051510).

  - kABI workaround for snd_seq_kernel_client_enqueue() API
    changes (bsc#1051510).

  - kbuild: modversions: Fix relative CRC byte order
    interpretation (bsc#1131290).

  - kbuild: strip whitespace in cmd_record_mcount findstring
    (bsc#1065729).

  - kcm: switch order of device registration to fix a crash
    (bnc#1130527).

  - kernel/sysctl.c: add missing range check in
    do_proc_dointvec_minmax_conv (bsc#1051510).

  - kernel/sysctl.c: fix out-of-bounds access when setting
    file-max (bsc#1051510).

  - kernfs: do not set dentry->d_fsdata (boo#1133115).

  - KEYS: always initialize keyring_index_key::desc_len
    (bsc#1051510).

  - KEYS: user: Align the payload buffer (bsc#1051510).

  - KVM: Call kvm_arch_memslots_updated() before updating
    memslots (bsc#1132563).

  - KVM: Fix kABI for AMD SMAP Errata workaround
    (bsc#1133149).

  - KVM: Fix UAF in nested posted interrupt processing
    (bsc#1134199).

  - KVM: nVMX: Apply addr size mask to effective address for
    VMX instructions (bsc#1132561).

  - KVM: nVMX: Clear reserved bits of #DB exit qualification
    (bsc#1134200).

  - KVM: nVMX: Ignore limit checks on VMX instructions using
    flat segments (bsc#1132564).

  - KVM: nVMX: restore host state in nested_vmx_vmexit for
    VMFail (bsc#1134201).

  - KVM: nVMX: Sign extend displacements of VMX instr's mem
    operands (bsc#1132562).

  - KVM: PPC: Book3S HV: Fix race between
    kvm_unmap_hva_range and MMU mode switch (bsc#1061840).

  - KVM: SVM: Workaround errata#1096 (insn_len maybe zero on
    SMAP violation) (bsc#1133149).

  - KVM: VMX: Compare only a single byte for VMCS'
    'launched' in vCPU-run (bsc#1132555).

  - KVM: VMX: Zero out *all* general purpose registers after
    VM-Exit (bsc#1134202).

  - KVM: x86: Always use 32-bit SMRAM save state for 32-bit
    kernels (bsc#1134203).

  - KVM: x86: Do not clear EFER during SMM transitions for
    32-bit vCPU (bsc#1134204).

  - KVM: x86: Emulate MSR_IA32_ARCH_CAPABILITIES on AMD
    hosts (bsc#1114279).

  - KVM: x86/mmu: Detect MMIO generation wrap in any address
    space (bsc#1132570).

  - KVM: x86/mmu: Do not cache MMIO accesses while memslots
    are in flux (bsc#1132571).

  - kvm: x86: Report STIBP on GET_SUPPORTED_CPUID
    (bsc#1111331).

  - KVM: x86: svm: make sure NMI is injected after
    nmi_singlestep (bsc#1134205).

  - leds: avoid races with workqueue (bsc#1051510).

  - leds: pca9532: fix a potential NULL pointer dereference
    (bsc#1051510).

  - lib: add crc64 calculation routines (bsc#1130972).

  - libata: fix using DMA buffers on stack (bsc#1051510).

  - lib: do not depend on linux headers being installed
    (bsc#1130972).

  - lightnvm: if LUNs are already allocated fix return
    (bsc#1085535).

  - linux/kernel.h: Use parentheses around argument in
    u64_to_user_ptr() (bsc#1051510).

  - Linux v5.0-rc7: bcm2835 MMC issues (bsc#1070872).

  - locking/atomics, asm-generic: Move some macros from
    <linux/bitops.h> to a new <linux/bits.h> file
    (bsc#1111331).

  - lpfc: validate command in
    lpfc_sli4_scmd_to_wqidx_distr() (bsc#1129138).

  - mac80211: do not call driver wake_tx_queue op during
    reconfig (bsc#1051510).

  - md: batch flush requests (bsc#1119680).

  - md: Fix failed allocation of md_register_thread
    (git-fixes).

  - md/raid1: do not clear bitmap bits on interrupted
    recovery (git-fixes).

  - md/raid5: fix 'out of memory' during raid cache recovery
    (git-fixes).

  - media: cx18: update *pos correctly in cx18_read_pos()
    (bsc#1051510).

  - media: cx23885: check allocation return (bsc#1051510).

  - media: davinci-isif: avoid uninitialized variable use
    (bsc#1051510).

  - media: ivtv: update *pos correctly in ivtv_read_pos()
    (bsc#1051510).

  - media: mt9m111: set initial frame size other than 0x0
    (bsc#1051510).

  - media: mtk-jpeg: Correct return type for mem2mem buffer
    helpers (bsc#1051510).

  - media: mx2_emmaprp: Correct return type for mem2mem
    buffer helpers (bsc#1051510).

  - media: ov2659: fix unbalanced mutex_lock/unlock
    (bsc#1051510).

  - media: pvrusb2: Prevent a buffer overflow (bsc#1129770).

  - media: s5p-g2d: Correct return type for mem2mem buffer
    helpers (bsc#1051510).

  - media: s5p-jpeg: Correct return type for mem2mem buffer
    helpers (bsc#1051510).

  - media: serial_ir: Fix use-after-free in
    serial_ir_init_module (bsc#1051510).

  - media: sh_veu: Correct return type for mem2mem buffer
    helpers (bsc#1051510).

  - media: tw5864: Fix possible NULL pointer dereference in
    tw5864_handle_frame (bsc#1051510).

  - media: vivid: use vfree() instead of kfree() for
    dev->bitmap_cap (bsc#1051510).

  - media: wl128x: Fix an error code in
    fm_download_firmware() (bsc#1051510).

  - media: wl128x: prevent two potential buffer overflows
    (bsc#1051510).

  - mISDN: hfcpci: Test both vendor & device ID for Digium
    HFC4S (bsc#1051510).

  - missing barriers in some of unix_sock ->addr and ->path
    accesses (networking-stable-19_03_15).

  - mmc: core: fix possible use after free of host
    (bsc#1051510).

  - mmc: davinci: remove extraneous __init annotation
    (bsc#1051510).

  - mmc: sdhci: Fix data command CRC error handling
    (bsc#1051510).

  - mmc: sdhci: Handle auto-command errors (bsc#1051510).

  - mmc: sdhci: Rename SDHCI_ACMD12_ERR and
    SDHCI_INT_ACMD12ERR (bsc#1051510).

  - mmc: tmio_mmc_core: do not claim spurious interrupts
    (bsc#1051510).

  - mm/debug.c: fix __dump_page when mapping->host is not
    set (bsc#1131934).

  - mm/huge_memory.c: fix modifying of page protection by
    insert_pfn_pmd() (bsc#1126740).

  - mm/page_isolation.c: fix a wrong flag in
    set_migratetype_isolate() (bsc#1131935).

  - mm/vmalloc: fix size check for
    remap_vmalloc_range_partial() (bsc#1133825).

  - mpls: Return error for RTA_GATEWAY attribute
    (networking-stable-19_03_07).

  - mt7601u: bump supported EEPROM version (bsc#1051510).

  - mtd: docg3: fix a possible memory leak of mtd->name
    (bsc#1051510).

  - mtd: docg3: Fix passing zero to 'PTR_ERR' warning in
    doc_probe_device (bsc#1051510).

  - mtd: nand: omap: Fix comment in platform data using
    wrong Kconfig symbol (bsc#1051510).

  - mtd: part: fix incorrect format specifier for an
    unsigned long long (bsc#1051510).

  - mtd: spi-nor: intel-spi: Avoid crossing 4K address
    boundary on read/write (bsc#1129770).

  - mwifiex: do not advertise IBSS features without FW
    support (bsc#1129770).

  - mwifiex: Fix mem leak in mwifiex_tm_cmd (bsc#1051510).

  - mwifiex: prevent an array overflow (bsc#1051510).

  - mwl8k: Fix rate_idx underflow (bsc#1051510).

  - net: Add header for usage of fls64()
    (networking-stable-19_02_20).

  - net: Add __icmp_send helper
    (networking-stable-19_03_07).

  - net: avoid false positives in untrusted gso validation
    (git-fixes).

  - net: avoid skb_warn_bad_offload on IS_ERR (git-fixes).

  - net: avoid use IPCB in cipso_v4_error
    (networking-stable-19_03_07).

  - net: bridge: add vlan_tunnel to bridge port policies
    (git-fixes).

  - net: bridge: fix per-port af_packet sockets (git-fixes).

  - net: bridge: multicast: use rcu to access port list from
    br_multicast_start_querier (git-fixes).

  - net: datagram: fix unbounded loop in
    __skb_try_recv_datagram() (git-fixes).

  - net: Do not allocate page fragments that are not skb
    aligned (networking-stable-19_02_20).

  - net: dsa: legacy: do not unmask port bitmaps
    (git-fixes).

  - net: dsa: mv88e6xxx: Fix u64 statistics
    (networking-stable-19_03_07).

  - netfilter: bridge: ebt_among: add missing match size
    checks (git-fixes).

  - netfilter: bridge: ebt_among: add more missing match
    size checks (git-fixes).

  - netfilter: bridge: set skb transport_header before
    entering NF_INET_PRE_ROUTING (git-fixes).

  - netfilter: drop template ct when conntrack is skipped
    (git-fixes).

  - netfilter: ip6t_MASQUERADE: add dependency on conntrack
    module (git-fixes).

  - netfilter: ipset: Missing nfnl_lock()/nfnl_unlock() is
    added to ip_set_net_exit() (git-fixes).

  - netfilter: ipv6: fix use-after-free Write in
    nf_nat_ipv6_manip_pkt (git-fixes).

  - netfilter: nf_socket: Fix out of bounds access in
    nf_sk_lookup_slow_v{4,6} (git-fixes).

  - netfilter: x_tables: avoid out-of-bounds reads in
    xt_request_find_{match|target} (git-fixes).

  - netfilter: x_tables: fix int overflow in
    xt_alloc_table_info() (git-fixes).

  - net: Fix for_each_netdev_feature on Big endian
    (networking-stable-19_02_20).

  - net: fix IPv6 prefix route residue
    (networking-stable-19_02_20).

  - net: Fix untag for vlan packets without ethernet header
    (git-fixes).

  - net: Fix vlan untag for bridge and vlan_dev with
    reorder_hdr off (git-fixes).

  - net/hsr: Check skb_put_padto() return value (git-fixes).

  - net: hsr: fix memory leak in hsr_dev_finalize()
    (networking-stable-19_03_15).

  - net/hsr: fix possible crash in add_timer()
    (networking-stable-19_03_15).

  - net/ibmvnic: Update carrier state after link state
    change (bsc#1135100).

  - net/ibmvnic: Update MAC address settings after adapter
    reset (bsc#1134760).

  - netlabel: fix out-of-bounds memory accesses
    (networking-stable-19_03_07).

  - netlink: fix nla_put_{u8,u16,u32} for KASAN (git-fixes).

  - net/mlx5e: Do not overwrite pedit action when multiple
    pedit used (networking-stable-19_02_24).

  - net: nfc: Fix NULL dereference on nfc_llcp_build_tlv
    fails (networking-stable-19_03_07).

  - net/packet: fix 4gb buffer limit due to overflow check
    (networking-stable-19_02_24).

  - net/packet: Set __GFP_NOWARN upon allocation in
    alloc_pg_vec (git-fixes).

  - net_sched: acquire RTNL in tc_action_net_exit()
    (git-fixes).

  - net_sched: fix two more memory leaks in cls_tcindex
    (networking-stable-19_02_24).

  - net: Set rtm_table to RT_TABLE_COMPAT for ipv6 for
    tables > 255 (networking-stable-19_03_15).

  - net: sit: fix memory leak in sit_init_net()
    (networking-stable-19_03_07).

  - net: sit: fix UBSAN Undefined behaviour in check_6rd
    (networking-stable-19_03_15).

  - net: socket: set sock->sk to NULL after calling
    proto_ops::release() (networking-stable-19_03_07).

  - net: validate untrusted gso packets without csum offload
    (networking-stable-19_02_20).

  - net/x25: fix a race in x25_bind()
    (networking-stable-19_03_15).

  - net/x25: fix use-after-free in x25_device_event()
    (networking-stable-19_03_15).

  - net/x25: reset state in x25_connect()
    (networking-stable-19_03_15).

  - net: xfrm: use preempt-safe this_cpu_read() in
    ipcomp_alloc_tfms() (git-fixes).

  - NFC: nci: Add some bounds checking in
    nci_hci_cmd_received() (bsc#1051510).

  - NFS: Add missing encode / decode sequence_maxsz to v4.2
    operations (git-fixes).

  - nfsd4: catch some false session retries (git-fixes).

  - nfsd4: fix cached replies to solo SEQUENCE compounds
    (git-fixes).

  - NFS: Do not recoalesce on error in
    nfs_pageio_complete_mirror() (git-fixes).

  - NFS: Do not use page_file_mapping after removing the
    page (git-fixes).

  - NFS: Fix an I/O request leakage in nfs_do_recoalesce
    (git-fixes).

  - NFS: Fix a soft lockup in the delegation recovery code
    (git-fixes).

  - NFS: Fix a typo in nfs_init_timeout_values()
    (git-fixes).

  - NFS: Fix dentry revalidation on NFSv4 lookup
    (bsc#1132618).

  - NFS: Fix I/O request leakages (git-fixes).

  - NFS: fix mount/umount race in nlmclnt (git-fixes).

  - NFS/pnfs: Bulk destroy of layouts needs to be safe
    w.r.t. umount (git-fixes).

  - NFSv4.1 do not free interrupted slot on open
    (git-fixes).

  - NFSv4.1: Reinitialise sequence results before
    retransmitting a request (git-fixes).

  - NFSv4/flexfiles: Fix invalid deref in
    FF_LAYOUT_DEVID_NODE() (git-fixes).

  - nvme: add proper discard setup for the multipath device
    (bsc#1114638).

  - nvme: fix the dangerous reference of namespaces list
    (bsc#1131673).

  - nvme: make sure ns head inherits underlying device
    limits (bsc#1131673).

  - nvme-multipath: avoid crash on invalid subsystem cntlid
    enumeration (bsc#1129273).

  - nvme-multipath: split bios with the ns_head bio_set
    before submitting (bsc#1103259, bsc#1131673).

  - nvme: only reconfigure discard if necessary
    (bsc#1114638).

  - ocfs2: fix inode bh swapping mixup in
    ocfs2_reflink_inodes_lock (bsc#1131169).

  - ocfs2: turn on OCFS2_FS_STATS setting(bsc#1134393) We
    need to turn on OCFS2_FS_STATS kernel configuration
    setting, to fix bsc#1134393.

  - omapfb: add missing of_node_put after
    of_device_is_available (bsc#1051510).

  - openvswitch: add seqadj extension when NAT is used
    (bsc#1051510).

  - openvswitch: fix flow actions reallocation
    (bsc#1051510).

  - packet: validate msg_namelen in send directly
    (git-fixes).

  - PCI: Add function 1 DMA alias quirk for Marvell 9170
    SATA controller (bsc#1051510).

  - PCI: designware-ep: Read-only registers need
    DBI_RO_WR_EN to be writable (bsc#1051510).

  - PCI: pciehp: Convert to threaded IRQ (bsc#1133005).

  - PCI: pciehp: Ignore Link State Changes after powering
    off a slot (bsc#1133005).

  - phy: sun4i-usb: Make sure to disable PHY0 passby for
    peripheral mode (bsc#1051510).

  - phy: sun4i-usb: Support set_mode to USB_HOST for non-OTG
    PHYs (bsc#1051510).

  - platform/x86: alienware-wmi: printing the wrong error
    code (bsc#1051510).

  - platform/x86: dell-rbtn: Add missing #include
    (bsc#1051510).

  - platform/x86: intel_pmc_ipc: adding error handling
    (bsc#1051510).

  - platform/x86: intel_punit_ipc: Revert 'Fix resource
    ioremap warning' (bsc#1051510).

  - platform/x86: pmc_atom: Drop __initconst on dmi table
    (bsc#1051510).

  - platform/x86: sony-laptop: Fix unintentional
    fall-through (bsc#1051510).

  - powerpc/64: Call setup_barrier_nospec() from
    setup_arch() (bsc#1131107).

  - powerpc/64: Disable the speculation barrier from the
    command line (bsc#1131107).

  - powerpc64/ftrace: Include ftrace.h needed for
    enable/disable calls (bsc#1088804, git-fixes).

  - powerpc/64: Make stf barrier PPC_BOOK3S_64 specific
    (bsc#1131107).

  - powerpc/64s: Add new security feature flags for count
    cache flush (bsc#1131107).

  - powerpc/64s: Add support for software count cache flush
    (bsc#1131107).

  - powerpc/64s: Fix logic when handling unknown CPU
    features (bsc#1055117).

  - powerpc/64s: Fix page table fragment refcount race vs
    speculative references (bsc#1131326, bsc#1108937).

  - powerpc/asm: Add a patch_site macro & helpers for
    patching instructions (bsc#1131107).

  - powerpc: avoid -mno-sched-epilog on GCC 4.9 and newer
    (bsc#1065729).

  - powerpc: consolidate -mno-sched-epilog into FTRACE flags
    (bsc#1065729).

  - powerpc: Fix 32-bit KVM-PR lockup and host crash with
    MacOS guest (bsc#1061840).

  - powerpc/fsl: Fix spectre_v2 mitigations reporting
    (bsc#1131107).

  - powerpc/hugetlb: Handle mmap_min_addr correctly in
    get_unmapped_area callback (bsc#1131900).

  - powerpc/kvm: Save and restore host AMR/IAMR/UAMOR
    (bsc#1061840).

  - powerpc/mm: Add missing tracepoint for tlbie
    (bsc#1055117, git-fixes).

  - powerpc/mm: Check secondary hash page table
    (bsc#1065729).

  - powerpc/mm: Fix page table dump to work on Radix
    (bsc#1055186, git-fixes).

  - powerpc/mm/hash: Handle mmap_min_addr correctly in
    get_unmapped_area topdown search (bsc#1131900).

  - powerpc/mm/radix: Display if mappings are exec or not
    (bsc#1055186, git-fixes).

  - powerpc/mm/radix: Prettify mapped memory range print out
    (bsc#1055186, git-fixes).

  - powerpc/numa: document topology_updates_enabled, disable
    by default (bsc#1133584).

  - powerpc/numa: improve control of topology updates
    (bsc#1133584).

  - powerpc/perf: Fix unit_sel/cache_sel checks
    (bsc#1053043).

  - powerpc/perf: Remove l2 bus events from HW cache event
    array (bsc#1053043).

  - powerpc/powernv/cpuidle: Init all present cpus for deep
    states (bsc#1055121).

  - powerpc/powernv: Do not reprogram SLW image on every KVM
    guest entry/exit (bsc#1061840).

  - powerpc/powernv/ioda2: Remove redundant free of TCE
    pages (bsc#1061840).

  - powerpc/powernv/ioda: Allocate indirect TCE levels of
    cached userspace addresses on demand (bsc#1061840).

  - powerpc/powernv/ioda: Fix locked_vm counting for memory
    used by IOMMU tables (bsc#1061840).

  - powerpc/powernv: Make opal log only readable by root
    (bsc#1065729).

  - powerpc/powernv: Query firmware for count cache flush
    settings (bsc#1131107).

  - powerpc/powernv: Remove never used pnv_power9_force_smt4
    (bsc#1061840).

  - powerpc/pseries: Query hypervisor for count cache flush
    settings (bsc#1131107).

  - powerpc/security: Fix spectre_v2 reporting
    (bsc#1131107).

  - powerpc/speculation: Support 'mitigations=' cmdline
    option (bsc#1112178).

  - powerpc/vdso32: fix CLOCK_MONOTONIC on PPC64
    (bsc#1131587).

  - powerpc/vdso64: Fix CLOCK_MONOTONIC inconsistencies
    across Y2038 (bsc#1131587).

  - proc/kcore: do not bounds check against address 0
    (bsc#1051510).

  - proc: revalidate kernel thread inodes to root:root
    (bsc#1051510).

  - proc/sysctl: fix return error for
    proc_doulongvec_minmax() (bsc#1051510).

  - pwm: Fix deadlock warning when removing PWM device
    (bsc#1051510).

  - pwm: meson: Consider 128 a valid pre-divider
    (bsc#1051510).

  - pwm: meson: Do not disable PWM when setting duty
    repeatedly (bsc#1051510).

  - pwm: meson: Use the spin-lock only to protect register
    modifications (bsc#1051510).

  - pwm: tiehrpwm: Update shadow register for disabling PWMs
    (bsc#1051510).

  - qla2xxx: allow irqbalance control in non-MQ mode
    (bsc#1128979).

  - qla2xxx: always allocate qla_tgt_wq (bsc#1131451).

  - qmi_wwan: add Olicard 600 (bsc#1051510).

  - qmi_wwan: Add support for Quectel EG12/EM12
    (networking-stable-19_03_07).

  - RAS/CEC: Check the correct variable in the debugfs error
    handling (bsc#1085535).

  - ravb: Decrease TxFIFO depth of Q3 and Q2 to one
    (networking-stable-19_03_15).

  - rdma/cxgb4: Add support for 64Byte cqes (bsc#1127371).

  - rdma/cxgb4: Add support for kernel mode SRQ's
    (bsc#1127371).

  - rdma/cxgb4: Add support for srq functions & structs
    (bsc#1127371).

  - rdma/cxgb4: fix some info leaks (bsc#1127371).

  - RDMA/cxgb4: Make c4iw_poll_cq_one() easier to analyze
    (bsc#1127371).

  - rdma/cxgb4: Remove a set-but-not-used variable
    (bsc#1127371).

  - RDMA/iw_cxgb4: Drop __GFP_NOFAIL (bsc#1127371).

  - rds: fix refcount bug in rds_sock_addref (git-fixes).

  - rds: tcp: atomically purge entries from
    rds_tcp_conn_list during netns delete (git-fixes).

  - Re-export snd_cards for kABI compatibility
    (bsc#1051510).

  - regulator: tps65086: Fix tps65086_ldoa1_ranges for
    selector 0xB (bsc#1051510).

  - Revert 'ALSA: seq: Protect in-kernel ioctl calls with
    mutex' (bsc#1051510).

  - Revert 'block: unexport DISK_EVENT_MEDIA_CHANGE for
    legacy/fringe drivers' (bsc#1110946, bsc#1119843).

  - Revert 'drm/sun4i: rgb: Change the pixel clock
    validation check (bnc#1113722)' 

  - Revert 'ide: unexport DISK_EVENT_MEDIA_CHANGE for ide-gd
    and ide-cd' (bsc#1110946).

  - Revert 'tty: pty: Fix race condition between
    release_one_tty and pty_write' (bsc#1051510).

  - ring-buffer: Check if memory is available before
    allocation (bsc#1132531).

  - route: set the deleted fnhe fnhe_daddr to 0 in
    ip_del_fnhe to fix a race (networking-stable-19_03_15).

  - rt2x00: do not increment sequence number while
    re-transmitting (bsc#1051510).

  - rtlwifi: rtl8723ae: Fix missing break in switch
    statement (bsc#1051510).

  - rxrpc: Do not release call mutex on error pointer
    (git-fixes).

  - rxrpc: Do not treat call aborts as conn aborts
    (git-fixes).

  - rxrpc: Fix client call queueing, waiting for channel
    (networking-stable-19_03_15).

  - rxrpc: Fix Tx ring annotation after initial Tx failure
    (git-fixes).

  - s390/dasd: fix panic for failed online processing
    (bsc#1132589).

  - s390/pkey: move pckmo subfunction available checks away
    from module init (bsc#1128544).

  - s390/speculation: Support 'mitigations=' cmdline option
    (bsc#1112178).

  - sc16is7xx: missing unregister/delete driver on error in
    sc16is7xx_init() (bsc#1051510).

  - sc16is7xx: move label 'err_spi' to correct section
    (bsc#1051510).

  - sc16is7xx: put err_spi and err_i2c into correct #ifdef
    (bsc#1051510).

  - scripts: override locale from environment when running
    recordmcount.pl (bsc#1134354).

  - scsi: libsas: allocate sense buffer for bsg queue
    (bsc#1131467).

  - scsi: qla2xxx: Add new FC-NVMe enable BIT to enable
    FC-NVMe feature (bsc#1130579).

  - scsi: qla2xxx: Fix panic in qla_dfs_tgt_counters_show
    (bsc#1132044).

  - sctp: call gso_reset_checksum when computing checksum in
    sctp_gso_segment (networking-stable-19_02_24).

  - sctp: only update outstanding_bytes for transmitted
    queue when doing prsctp_prune (git-fixes).

  - sctp: set frag_point in sctp_setsockopt_maxseg
    correctly` (git-fixes).

  - selinux: use kernel linux/socket.h for genheaders and
    mdp (bsc#1134810).

  - serial: 8250_pxa: honor the port number from devicetree
    (bsc#1051510).

  - serial: ar933x_uart: Fix build failure with disabled
    console (bsc#1051510).

  - serial: max310x: Fix to avoid potential NULL pointer
    dereference (bsc#1051510).

  - serial: sh-sci: Fix setting SCSCR_TIE while transferring
    data (bsc#1051510).

  - serial: uartps: console_setup() can't be placed to init
    section (bsc#1051510).

  - sit: check if IPv6 enabled before calling
    ip6_err_gen_icmpv6_unreach()
    (networking-stable-19_02_24).

  - SoC: imx-sgtl5000: add missing put_device()
    (bsc#1051510).

  - soc: qcom: gsbi: Fix error handling in gsbi_probe()
    (bsc#1051510).

  - soc/tegra: fuse: Fix illegal free of IO base address
    (bsc#1051510).

  - soc/tegra: pmc: Drop locking from
    tegra_powergate_is_powered() (bsc#1051510).

  - spi: a3700: Clear DATA_OUT when performing a read
    (bsc#1051510).

  - spi: bcm2835aux: fix driver to not allow 65535 (=-1)
    cs-gpios (bsc#1051510).

  - spi: bcm2835aux: setup gpio-cs to output and correct
    level during setup (bsc#1051510).

  - spi: bcm2835aux: warn in dmesg that native cs is not
    really supported (bsc#1051510).

  - spi: rspi: Fix sequencer reset during initialization
    (bsc#1051510).

  - ssb: Fix possible NULL pointer dereference in
    ssb_host_pcmcia_exit (bsc#1051510).

  - staging: comedi: ni_usb6501: Fix possible double-free of
    ->usb_rx_buf (bsc#1051510).

  - staging: comedi: ni_usb6501: Fix use of uninitialized
    mutex (bsc#1051510).

  - staging: comedi: vmk80xx: Fix possible double-free of
    ->usb_rx_buf (bsc#1051510).

  - staging: comedi: vmk80xx: Fix use of uninitialized
    semaphore (bsc#1051510).

  - staging: iio: ad7192: Fix ad7193 channel address
    (bsc#1051510).

  - staging: rtl8188eu: Fix potential NULL pointer
    dereference of kcalloc (bsc#1051510).

  - staging: rtl8712: uninitialized memory in
    read_bbreg_hdl() (bsc#1051510).

  - staging: vt6655: Fix interrupt race condition on device
    start up (bsc#1051510).

  - staging: vt6655: Remove vif check from vnt_interrupt
    (bsc#1051510).

  - stm class: Fix an endless loop in channel allocation
    (bsc#1051510).

  - stm class: Fix channel free in stm output free path
    (bsc#1051510).

  - stm class: Prevent division by zero (bsc#1051510).

  - sunrpc/cache: handle missing listeners better
    (bsc#1126221).

  - sunrpc: fix 4 more call sites that were using stack
    memory with a scatterlist (git-fixes).

  - supported.conf: Add openvswitch to kernel-default-base
    (bsc#1124839).

  - supported.conf: Add vxlan to kernel-default-base
    (bsc#1132083).

  - supported.conf: dw_mmc-bluefield is not needed in
    kernel-default-base (bsc#1131574).

  - svm/avic: Fix invalidate logical APIC id entry
    (bsc#1132726).

  - svm: Fix AVIC DFR and LDR handling (bsc#1132558).

  - sysctl: handle overflow for file-max (bsc#1051510).

  - tcp: fix TCP_REPAIR_QUEUE bound checking (git-fixes).

  - tcp: tcp_v4_err() should be more careful
    (networking-stable-19_02_20).

  - thermal/int340x_thermal: Add additional UUIDs
    (bsc#1051510).

  - thermal/int340x_thermal: fix mode setting (bsc#1051510).

  - tipc: fix race condition causing hung sendto
    (networking-stable-19_03_07).

  - tpm: Fix the type of the return value in
    calc_tpm2_event_size() (bsc#1082555).

  - tracing: Fix a memory leak by early error exit in
    trace_pid_write() (bsc#1133702).

  - tracing: Fix buffer_ref pipe ops (bsc#1133698).

  - tracing/hrtimer: Fix tracing bugs by taking all clock
    bases and modes into account (bsc#1132527).

  - tty: atmel_serial: fix a potential NULL pointer
    dereference (bsc#1051510).

  - tty: increase the default flip buffer limit to 2*640K
    (bsc#1051510).

  - tty: pty: Fix race condition between release_one_tty and
    pty_write (bsc#1051510).

  - tty: vt.c: Fix TIOCL_BLANKSCREEN console blanking if
    blankinterval == 0 (bsc#1051510).

  - tun: fix blocking read (networking-stable-19_03_07).

  - tun: remove unnecessary memory barrier
    (networking-stable-19_03_07).

  - UAS: fix alignment of scatter/gather segments
    (bsc#1129770).

  - udf: Fix crash on IO error during truncate
    (bsc#1131175).

  - usb: cdc-acm: fix unthrottle races (bsc#1051510).

  - usb: chipidea: Grab the (legacy) USB PHY by phandle
    first (bsc#1051510).

  - usb: core: Fix bug caused by duplicate interface PM
    usage counter (bsc#1051510).

  - usb: core: Fix unterminated string returned by
    usb_string() (bsc#1051510).

  - usb: dwc3: Fix default lpm_nyet_threshold value
    (bsc#1051510).

  - usb: f_fs: Avoid crash due to out-of-scope stack ptr
    access (bsc#1051510).

  - usb: gadget: net2272: Fix net2272_dequeue()
    (bsc#1051510).

  - usb: gadget: net2280: Fix net2280_dequeue()
    (bsc#1051510).

  - usb: gadget: net2280: Fix overrun of OUT messages
    (bsc#1051510).

  - usb: host: xhci-rcar: Add XHCI_TRUST_TX_LENGTH quirk
    (bsc#1051510).

  - usb: mtu3: fix EXTCON dependency (bsc#1051510).

  - usb: serial: cp210x: add new device id (bsc#1051510).

  - usb: serial: cp210x: fix GPIO in autosuspend
    (bsc#1120902).

  - usb: serial: f81232: fix interrupt worker not stop
    (bsc#1051510).

  - usb: serial: fix unthrottle races (bsc#1051510).

  - usb: serial: ftdi_sio: add additional NovaTech products
    (bsc#1051510).

  - usb: serial: option: add Olicard 600 (bsc#1051510).

  - usb: serial: option: add support for Quectel EM12
    (bsc#1051510).

  - usb-storage: Set virt_boundary_mask to avoid SG
    overflows (bsc#1051510).

  - usb: u132-hcd: fix resource leak (bsc#1051510).

  - usb: usb251xb: fix to avoid potential NULL pointer
    dereference (bsc#1051510).

  - usb: usbip: fix isoc packet num validation in get_pipe
    (bsc#1051510).

  - usb: w1 ds2490: Fix bug caused by improper use of
    altsetting array (bsc#1051510).

  - usb: yurex: Fix protection fault after device removal
    (bsc#1051510).

  - vfio/mdev: Avoid release parent reference during error
    path (bsc#1051510).

  - vfio/mdev: Fix aborting mdev child device removal if one
    fails (bsc#1051510).

  - vfio_pci: Enable memory accesses before calling
    pci_map_rom (bsc#1051510).

  - vfio/pci: use correct format characters (bsc#1051510).

  - vfs: allow dedupe of user owned read-only files
    (bsc#1133778, bsc#1132219).

  - vfs: avoid problematic remapping requests into partial
    EOF block (bsc#1133850, bsc#1132219).

  - vfs: dedupe: extract helper for a single dedup
    (bsc#1133769, bsc#1132219).

  - vfs: dedupe should return EPERM if permission is not
    granted (bsc#1133779, bsc#1132219).

  - vfs: exit early from zero length remap operations
    (bsc#1132411, bsc#1132219).

  - vfs: export vfs_dedupe_file_range_one() to modules
    (bsc#1133772, bsc#1132219).

  - vfs: limit size of dedupe (bsc#1132397, bsc#1132219).

  - vfs: rename clone_verify_area to remap_verify_area
    (bsc#1133852, bsc#1132219).

  - vfs: skip zero-length dedupe requests (bsc#1133851,
    bsc#1132219).

  - vfs: swap names of {do,vfs}_clone_file_range()
    (bsc#1133774, bsc#1132219).

  - vfs: vfs_clone_file_prep_inodes should return EINVAL for
    a clone from beyond EOF (bsc#1133780, bsc#1132219).

  - vhost/vsock: fix reset orphans race with close timeout
    (bsc#1051510).

  - video: fbdev: Set pixclock = 0 in goldfishfb
    (bsc#1051510).

  - virtio-blk: limit number of hw queues by nr_cpu_ids
    (bsc#1051510).

  - virtio: Honour 'may_reduce_num' in
    vring_create_virtqueue (bsc#1051510).

  - virtio_pci: fix a NULL pointer reference in vp_del_vqs
    (bsc#1051510).

  - vsock/virtio: fix kernel panic after device hot-unplug
    (bsc#1051510).

  - vsock/virtio: fix kernel panic from
    virtio_transport_reset_no_sock (bsc#1051510).

  - vsock/virtio: reset connected sockets on device removal
    (bsc#1051510).

  - vxlan: test dev->flags & IFF_UP before calling
    netif_rx() (networking-stable-19_02_20).

  - wil6210: check NULL pointer in
    _wil_cfg80211_merge_extra_ies (bsc#1051510).

  - wlcore: Fix memory leak in case wl12xx_fetch_firmware
    failure (bsc#1051510).

  - x86/cpu: Sanitize FAM6_ATOM naming (bsc#1111331).

  - x86/kvm: Expose X86_FEATURE_MD_CLEAR to guests
    (bsc#1111331).

  - x86/kvm/hyper-v: avoid spurious pending stimer on vCPU
    init (bsc#1132572).

  - x86/kvm/vmx: Add MDS protection when L1D Flush is not
    active (bsc#1111331).

  - x86/MCE/AMD, EDAC/mce_amd: Add new error descriptions
    for some SMCA bank types (bsc#1128415).

  - x86/MCE/AMD, EDAC/mce_amd: Add new McaTypes for CS, PSP,
    and SMU units (bsc#1128415).

  - x86/MCE/AMD, EDAC/mce_amd: Add new MP5, NBIO, and PCIE
    SMCA bank types (bsc#1128415).

  - x86/mce/AMD, EDAC/mce_amd: Enumerate Reserved SMCA bank
    type (bsc#1128415).

  - x86/mce/AMD: Pass the bank number to
    smca_get_bank_type() (bsc#1128415).

  - x86/MCE: Fix kABI for new AMD bank names (bsc#1128415).

  - x86/mce: Handle varying MCA bank counts (bsc#1128415).

  - x86/msr-index: Cleanup bit defines (bsc#1111331).

  - x86/PCI: Fixup RTIT_BAR of Intel Denverton Trace Hub
    (bsc#1120318).

  - x86/speculation: Consolidate CPU whitelists
    (bsc#1111331).

  - x86/speculation/mds: Add basic bug infrastructure for
    MDS (bsc#1111331).

  - x86/speculation/mds: Add BUG_MSBDS_ONLY (bsc#1111331).

  - x86/speculation/mds: Add mds_clear_cpu_buffers()
    (bsc#1111331).

  - x86/speculation/mds: Add mds=full,nosmt cmdline option
    (bsc#1111331).

  - x86/speculation/mds: Add mitigation control for MDS
    (bsc#1111331).

  - x86/speculation/mds: Add mitigation mode VMWERV
    (bsc#1111331).

  - x86/speculation/mds: Add 'mitigations=' support for MDS
    (bsc#1111331).

  - x86/speculation/mds: Add SMT warning message
    (bsc#1111331).

  - x86/speculation/mds: Add sysfs reporting for MDS
    (bsc#1111331).

  - x86/speculation/mds: Clear CPU buffers on exit to user
    (bsc#1111331).

  - x86/speculation/mds: Conditionally clear CPU buffers on
    idle entry (bsc#1111331).

  - x86/speculation/mds: Print SMT vulnerable on MSBDS with
    mitigations off (bsc#1111331).

  - x86/speculation: Move arch_smt_update() call to after
    mitigation decisions (bsc#1111331).

  - x86/speculation: Prevent deadlock on ssb_state::lock
    (bsc#1114279).

  - x86/speculation: Simplify the CPU bug detection logic
    (bsc#1111331).

  - x86/speculation: Support 'mitigations=' cmdline option
    (bsc#1112178).

  - x86/tsc: Force inlining of cyc2ns bits (bsc#1052904).

  - xen-netback: do not populate the hash cache on XenBus
    disconnect (networking-stable-19_03_07).

  - xen-netback: fix occasional leak of grant ref mappings
    under memory pressure (networking-stable-19_03_07).

  - xen: Prevent buffer overflow in privcmd ioctl
    (bsc#1065600).

  - xfrm: do not call rcu_read_unlock when afinfo is NULL in
    xfrm_get_tos (git-fixes).

  - xfrm: Fix ESN sequence number handling for IPsec GSO
    packets (git-fixes).

  - xfrm: fix rcu_read_unlock usage in xfrm_local_error
    (git-fixes).

  - xfrm: Fix stack-out-of-bounds read on socket policy
    lookup (git-fixes).

  - xfrm: fix xfrm_do_migrate() with AEAD e.g(AES-GCM)
    (git-fixes).

  - xfrm: Return error on unknown encap_type in init_state
    (git-fixes).

  - xfs: add the ability to join a held buffer to a
    defer_ops (bsc#1133674).

  - xfs: allow xfs_lock_two_inodes to take different
    EXCL/SHARED modes (bsc#1132370, bsc#1132219).

  - xfs: call xfs_qm_dqattach before performing reflink
    operations (bsc#1132368, bsc#1132219).

  - xfs: cap the length of deduplication requests
    (bsc#1132373, bsc#1132219).

  - xfs: clean up xfs_reflink_remap_blocks call site
    (bsc#1132413, bsc#1132219).

  - xfs: detect and fix bad summary counts at mount
    (bsc#1114427).

  - xfs: fix data corruption w/ unaligned dedupe ranges
    (bsc#1132405, bsc#1132219).

  - xfs: fix data corruption w/ unaligned reflink ranges
    (bsc#1132407, bsc#1132219).

  - xfs: fix pagecache truncation prior to reflink
    (bsc#1132412, bsc#1132219).

  - xfs: fix reporting supported extra file attributes for
    statx() (bsc#1133529).

  - xfs: flush removing page cache in xfs_reflink_remap_prep
    (bsc#1132414, bsc#1132219).

  - xfs: hold xfs_buf locked between shortform->leaf
    conversion and the addition of an attribute
    (bsc#1133675).

  - xfs: kill meaningless variable 'zero' (bsc#1106011).

  - xfs: only grab shared inode locks for source file during
    reflink (bsc#1132372, bsc#1132219).

  - xfs: prepare xfs_break_layouts() for another layout type
    (bsc#1106011).

  - xfs: prepare xfs_break_layouts() to be called with
    XFS_MMAPLOCK_EXCL (bsc#1106011).

  - xfs: refactor clonerange preparation into a separate
    helper (bsc#1132402, bsc#1132219).

  - xfs: refactor xfs_trans_roll (bsc#1133667).

  - xfs: reflink find shared should take a transaction
    (bsc#1132226, bsc#1132219).

  - xfs: reflink should break pnfs leases before sharing
    blocks (bsc#1132369, bsc#1132219).

  - xfs: remove dest file's post-eof preallocations before
    reflinking (bsc#1132365, bsc#1132219).

  - xfs: remove the ip argument to xfs_defer_finish
    (bsc#1133672).

  - xfs: remove xfs_zero_range (bsc#1106011).

  - xfs: rename xfs_defer_join to xfs_defer_ijoin
    (bsc#1133668).

  - xfs: update ctime and remove suid before cloning files
    (bsc#1132404, bsc#1132219).

  - xfs: zero posteof blocks when cloning above eof
    (bsc#1132403, bsc#1132219).

  - xhci: Do not let USB3 ports stuck in polling state
    prevent suspend (bsc#1051510).

  - xhci: Fix port resume done detection for SS ports with
    LPM enabled (bsc#1051510)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055186"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082555"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108937"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114427"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130579"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131336"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131574"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131851"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132572"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133149"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133672"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133852"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134537"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135100"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/17");
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

if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-debuginfo-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debuginfo-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debugsource-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-debuginfo-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-debuginfo-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debuginfo-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debugsource-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-debuginfo-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-devel-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-docs-html-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debugsource-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-macros-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-debugsource-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-qa-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-vanilla-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-syms-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debuginfo-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debugsource-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-4.12.14-lp150.12.61.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp150.12.61.1") ) flag++;

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
