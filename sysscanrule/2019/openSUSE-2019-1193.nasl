#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1193.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(124050);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/30 14:30:16");

  script_cve_id("CVE-2019-2024", "CVE-2019-3819", "CVE-2019-7308", "CVE-2019-8912", "CVE-2019-8980", "CVE-2019-9213");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-1193)");
  script_summary(english:"Check for the openSUSE-2019-1193 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 15.0 was updated to receive various security and
bugfixes.

The following security bugs were fixed :

  - CVE-2019-2024: A use-after-free when disconnecting a
    source was fixed which could lead to crashes.
    bnc#1129179).

  - CVE-2019-3819: A flaw was found in the Linux kernel in
    the function hid_debug_events_read() in
    drivers/hid/hid-debug.c file which may enter an infinite
    loop with certain parameters passed from a userspace. A
    local privileged user ('root') can cause a system lock
    up and a denial of service. Versions from v4.18 and
    newer are vulnerable (bnc#1123161).

  - CVE-2019-7308: kernel/bpf/verifier.c performed
    undesirable out-of-bounds speculation on pointer
    arithmetic in various cases, including cases of
    different branches with different state or limits to
    sanitize, leading to side-channel attacks (bnc#1124055).

  - CVE-2019-8912: af_alg_release() in crypto/af_alg.c
    neglected to set a NULL value for a certain structure
    member, which leads to a use-after-free in
    sockfs_setattr (bnc#1125907).

  - CVE-2019-8980: A memory leak in the kernel_read_file
    function in fs/exec.c allowed attackers to cause a
    denial of service (memory consumption) by triggering
    vfs_read failures (bnc#1126209).

  - CVE-2019-9213: expand_downwards in mm/mmap.c lacked a
    check for the mmap minimum address, which made it easier
    for attackers to exploit kernel NULL pointer
    dereferences on non-SMAP platforms. This is related to a
    capability check for the wrong task (bnc#1128166).

The following non-security bugs were fixed :

  - 9p/net: fix memory leak in p9_client_create
    (bsc#1051510).

  - 9p: use inode->i_lock to protect i_size_write() under
    32-bit (bsc#1051510).

  - acpi: acpi_pad: Do not launch acpi_pad threads on idle
    cpus (bsc#1113399).

  - acpi/APEI: Clear GHES block_status before panic()
    (bsc#1051510).

  - acpi/device_sysfs: Avoid OF modalias creation for
    removed device (bsc#1051510).

  - acpi/nfit: Fix bus command validation (bsc#1051510).

  - acpi: NUMA: Use correct type for printing addresses on
    i386-PAE (bsc#1051510).

  - acpi / video: Extend chassis-type detection with a
    'Lunch Box' check (bsc#1051510).

  - acpi / video: Refactor and fix dmi_is_desktop()
    (bsc#1051510).

  - alsa: bebob: use more identical mod_alias for Saffire
    Pro 10 I/O against Liquid Saffire 56 (bsc#1051510).

  - alsa: compress: prevent potential divide by zero bugs
    (bsc#1051510).

  - alsa: echoaudio: add a check for ioremap_nocache
    (bsc#1051510).

  - alsa: firewire: add const qualifier to identifiers for
    read-only symbols (bsc#1051510).

  - alsa: firewire-motu: add a flag for AES/EBU on XLR
    interface (bsc#1051510).

  - alsa: firewire-motu: add specification flag for position
    of flag for MIDI messages (bsc#1051510).

  - alsa: firewire-motu: add support for MOTU Audio Express
    (bsc#1051510).

  - alsa: firewire-motu: add support for Motu Traveler
    (bsc#1051510).

  - alsa: firewire-motu: fix construction of PCM frame for
    capture direction (bsc#1051510).

  - alsa: firewire-motu: use 'version' field of unit
    directory to identify model (bsc#1051510).

  - alsa: hda - add Lenovo IdeaCentre B550 to the
    power_save_blacklist (bsc#1051510).

  - alsa: hda - Add quirk for HP EliteBook 840 G5
    (bsc#1051510).

  - alsa: hda - Enforces runtime_resume after S3 and S4 for
    each codec (bsc#1051510).

  - alsa: hda/realtek - Add support for Acer Aspire
    E5-523G/ES1-432 headset mic (bsc#1051510).

  - alsa: hda/realtek: Disable PC beep in passthrough on
    alc285 (bsc#1051510).

  - alsa: hda/realtek: Enable ASUS X441MB and X705FD headset
    MIC with ALC256 (bsc#1051510).

  - alsa: hda/realtek: Enable audio jacks of ASUS UX362FA
    with ALC294 (bsc#1051510).

  - alsa: hda/realtek: Enable headset MIC of Acer AIO with
    ALC286 (bsc#1051510).

  - alsa: hda/realtek: Enable headset MIC of Acer Aspire
    Z24-890 with ALC286 (bsc#1051510).

  - alsa: hda/realtek: Enable headset mic of ASUS P5440FF
    with ALC256 (bsc#1051510).

  - alsa: hda/realtek - Headset microphone and internal
    speaker support for System76 oryp5 (bsc#1051510).

  - alsa: hda/realtek - Headset microphone support for
    System76 darp5 (bsc#1051510).

  - alsa: hda/realtek - Reduce click noise on Dell Precision
    5820 headphone (bsc#1126131).

  - alsa: hda - Record the current power state before
    suspend/resume calls (bsc#1051510).

  - alsa: opl3: fix mismatch between snd_opl3_drum_switch
    definition and declaration (bsc#1051510).

  - alsa: pcm: Do not suspend stream in unrecoverable PCM
    state (bsc#1051510).

  - alsa: pcm: Fix possible OOB access in PCM oss plugins
    (bsc#1051510).

  - alsa: rawmidi: Fix potential Spectre v1 vulnerability
    (bsc#1051510).

  - alsa: sb8: add a check for request_region (bsc#1051510).

  - alsa: seq: oss: Fix Spectre v1 vulnerability
    (bsc#1051510).

  - alsa: usb-audio: Fix implicit fb endpoint setup by quirk
    (bsc#1051510).

  - altera-stapl: check for a null key before strcasecmp'ing
    it (bsc#1051510).

  - apparmor: Fix aa_label_build() error handling for failed
    merges (bsc#1051510).

  - applicom: Fix potential Spectre v1 vulnerabilities
    (bsc#1051510).

  - aquantia: Setup max_mtu in ndev to enable jumbo frames
    (bsc#1051510).

  - arm64: fault: avoid send SIGBUS two times (bsc#1126393).

  - arm: 8808/1: kexec:offline panic_smp_self_stop CPU
    (bsc#1051510).

  - arm/arm64: KVM: Rename function
    kvm_arch_dev_ioctl_check_extension() (bsc#1126393).

  - arm: iop32x/n2100: fix PCI IRQ mapping (bsc#1051510).

  - arm: OMAP2+: hwmod: Fix some section annotations
    (bsc#1051510).

  - arm: pxa: avoid section mismatch warning (bsc#1051510).

  - arm: tango: Improve ARCH_MULTIPLATFORM compatibility
    (bsc#1051510).

  - ASoC: atom: fix a missing check of
    snd_pcm_lib_malloc_pages (bsc#1051510).

  - ASoC: dapm: change snprintf to scnprintf for possible
    overflow (bsc#1051510).

  - ASoC: fsl_esai: fix register setting issue in RIGHT_J
    mode (bsc#1051510).

  - ASoC: fsl: Fix SND_SOC_EUKREA_TLV320 build error on
    i.MX8M (bsc#1051510).

  - ASoC: imx-audmux: change snprintf to scnprintf for
    possible overflow (bsc#1051510).

  - ASoC: imx-sgtl5000: put of nodes if finding codec fails
    (bsc#1051510).

  - ASoC: Intel: Haswell/Broadwell: fix setting for .dynamic
    field (bsc#1051510).

  - ASoC: msm8916-wcd-analog: add missing license
    information (bsc#1051510).

  - ASoC: qcom: Fix of-node refcount unbalance in
    apq8016_sbc_parse_of() (bsc#1051510).

  - ASoC: rsnd: fixup rsnd_ssi_master_clk_start() user count
    check (bsc#1051510).

  - assoc_array: Fix shortcut creation (bsc#1051510).

  - ata: ahci: mvebu: remove stale comment (bsc#1051510).

  - ath9k: Avoid OF no-EEPROM quirks without qca,no-eeprom
    (bsc#1051510).

  - ath9k: dynack: check da->enabled first in sampling
    routines (bsc#1051510).

  - ath9k: dynack: make ewma estimation faster
    (bsc#1051510).

  - ath9k: dynack: use authentication messages for 'late'
    ack (bsc#1051510).

  - atm: he: fix sign-extension overflow on large shift
    (bsc#1051510).

  - auxdisplay: hd44780: Fix memory leak on ->remove()
    (bsc#1051510).

  - auxdisplay: ht16k33: fix potential user-after-free on
    module unload (bsc#1051510).

  - ax25: fix possible use-after-free (bsc#1051510).

  - backlight: pwm_bl: Use gpiod_get_value_cansleep() to get
    initial (bsc#1113722)

  - batman-adv: Avoid WARN on net_device without parent in
    netns (bsc#1051510).

  - batman-adv: fix uninit-value in batadv_interface_tx()
    (bsc#1051510).

  - batman-adv: Force mac header to start of data on xmit
    (bsc#1051510).

  - bio: Introduce BIO_ALLOCED flag and check it in bio_free
    (bsc#1128094).

  - blk-mq: fix a hung issue when fsync (bsc#1125252).

  - block_dev: fix crash on chained bios with O_DIRECT
    (bsc#1128094).

  - block_dev: fix crash on chained bios with O_DIRECT
    (bsc#1128094).

  - blockdev: Fix livelocks on loop device (bsc#1124984).

  - block: do not use bio->bi_vcnt to figure out segment
    number (bsc#1128895).

  - block: do not warn when doing fsync on read-only devices
    (bsc#1125252).

  - block/loop: Use global lock for ioctl() operation
    (bsc#1124974).

  - block: move bio_integrity_{intervals,bytes} into
    blkdev.h (bsc#1114585).

  - bluetooth: Fix decrementing reference count twice in
    releasing socket (bsc#1051510).

  - bluetooth: Fix locking in bt_accept_enqueue() for BH
    context (bsc#1051510).

  - bluetooth: Fix unnecessary error message for HCI request
    completion (bsc#1051510).

  - bluetooth: hci_ldisc: Initialize hci_dev before open()
    (bsc#1051510).

  - bluetooth: hci_ldisc: Postpone HCI_UART_PROTO_READY bit
    set in hci_uart_set_proto() (bsc#1051510).

  - bnxt_en: Fix typo in firmware message timeout logic
    (bsc#1086282 ).

  - bnxt_en: Wait longer for the firmware message response
    to complete (bsc#1086282).

  - bpf: decrease usercnt if bpf_map_new_fd() fails in
    bpf_map_get_fd_by_id() (bsc#1083647).

  - bpf: drop refcount if bpf_map_new_fd() fails in
    map_create() (bsc#1083647).

  - bpf: fix lockdep false positive in percpu_freelist
    (bsc#1083647).

  - bpf: fix replace_map_fd_with_map_ptr's ldimm64 second
    imm field (bsc#1083647).

  - bpf: fix sanitation rewrite in case of non-pointers
    (bsc#1083647).

  - bpf: Fix syscall's stackmap lookup potential deadlock
    (bsc#1083647).

  - bpf, lpm: fix lookup bug in map_delete_elem
    (bsc#1083647).

  - bpf/verifier: fix verifier instability (bsc#1056787).

  - bsg: Do not copy sense if no response buffer is
    allocated (bsc#1106811,bsc#1126555).

  - btrfs: dedupe_file_range ioctl: remove 16MiB restriction
    (bsc#1127494).

  - btrfs: do not unnecessarily pass write_lock_level when
    processing leaf (bsc#1126802).

  - btrfs: ensure that a DUP or RAID1 block group has
    exactly two stripes (bsc#1128451).

  - btrfs: fix clone vs chattr NODATASUM race (bsc#1127497).

  - btrfs: fix corruption reading shared and compressed
    extents after hole punching (bsc#1126476).

  - btrfs: fix deadlock between clone/dedupe and rename
    (bsc#1130518).

  - btrfs: fix deadlock when allocating tree block during
    leaf/node split (bsc#1126806).

  - btrfs: fix deadlock when using free space tree due to
    block group creation (bsc#1126804).

  - btrfs: fix fsync after succession of renames and
    unlink/rmdir (bsc#1126488).

  - btrfs: fix fsync after succession of renames of
    different files (bsc#1126481).

  - btrfs: fix invalid-free in btrfs_extent_same
    (bsc#1127498).

  - btrfs: fix reading stale metadata blocks after degraded
    raid1 mounts (bsc#1126803).

  - btrfs: fix use-after-free of cmp workspace pages
    (bsc#1127603).

  - btrfs: grab write lock directly if write_lock_level is
    the max level (bsc#1126802).

  - btrfs: Improve btrfs_search_slot description
    (bsc#1126802).

  - btrfs: move get root out of btrfs_search_slot to a
    helper (bsc#1126802).

  - btrfs: qgroup: Cleanup old subtree swap code
    (bsc#1063638).

  - btrfs: qgroup: Do not trace subtree if we're dropping
    reloc tree (bsc#1063638).

  - btrfs: qgroup: Finish rescan when hit the last leaf of
    extent tree (bsc#1129327).

  - btrfs: qgroup: Introduce function to find all new tree
    blocks of reloc tree (bsc#1063638).

  - btrfs: qgroup: Introduce function to trace two swaped
    extents (bsc#1063638).

  - btrfs: qgroup: Introduce per-root swapped blocks
    infrastructure (bsc#1063638).

  - btrfs: qgroup: Introduce trace event to analyse the
    number of dirty extents accounted (bsc#1063638
    dependency).

  - btrfs: qgroup: Make qgroup async transaction commit more
    aggressive (bsc#1113042).

  - btrfs: qgroup: Only trace data extents in leaves if
    we're relocating data block group (bsc#1063638).

  - btrfs: qgroup: Refactor btrfs_qgroup_trace_subtree_swap
    (bsc#1063638).

  - btrfs: qgroup: Search commit root for rescan to avoid
    missing extent (bsc#1129326).

  - btrfs: qgroup: Use delayed subtree rescan for balance
    (bsc#1063638).

  - btrfs: qgroup: Use generation-aware subtree swap to mark
    dirty extents (bsc#1063638).

  - btrfs: quota: Set rescan progress to (u64)-1 if we hit
    last leaf (bsc#1129327).

  - btrfs: relocation: Delay reloc tree deletion after
    merge_reloc_roots (bsc#1063638).

  - btrfs: reloc: Fix NULL pointer dereference due to
    expanded reloc_root lifespan (bsc#1129497).

  - btrfs: remove always true check in unlock_up
    (bsc#1126802).

  - btrfs: remove superfluous free_extent_buffer in
    read_block_for_search (bsc#1126802).

  - btrfs: remove unnecessary level check in balance_level
    (bsc#1126802).

  - btrfs: remove unused check of skip_locking
    (bsc#1126802).

  - btrfs: reuse cmp workspace in EXTENT_SAME ioctl
    (bsc#1127495).

  - btrfs: send, fix race with transaction commits that
    create snapshots (bsc#1126802).

  - btrfs: simplify IS_ERR/PTR_ERR checks (bsc#1126481).

  - btrfs: split btrfs_extent_same (bsc#1127493).

  - btrfs: use kvzalloc for EXTENT_SAME temporary data
    (bsc#1127496).

  - btrfs: use more straightforward extent_buffer_uptodate
    check (bsc#1126802).

  - cdc-wdm: pass return value of recover_from_urb_loss
    (bsc#1051510).

  - ceph: avoid repeatedly adding inode to
    mdsc->snap_flush_list (bsc#1126790).

  - ceph: clear inode pointer when snap realm gets dropped
    by its inode (bsc#1125799).

  - cfg80211: extend range deviation for DMG (bsc#1051510).

  - ch: add missing mutex_lock()/mutex_unlock() in
    ch_release() (bsc#1124235).

  - ch: fixup refcounting imbalance for SCSI devices
    (bsc#1124235).

  - cifs: allow guest mounts to work for smb3.11
    (bsc#1051510).

  - cifs: Always resolve hostname before reconnecting
    (bsc#1051510).

  - cifs: connect to servername instead of IP for IPC$ share
    (bsc#1051510).

  - cifs: Fix NULL pointer dereference of devname
    (bnc#1129519).

  - cifs: invalidate cache when we truncate a file
    (bsc#1051510).

  - cifs: OFD locks do not conflict with eachothers
    (bsc#1051510).

  - clk: armada-370: fix refcount leak in a370_clk_init()
    (bsc#1051510).

  - clk: armada-xp: fix refcount leak in axp_clk_init()
    (bsc#1051510).

  - clk: clk-twl6040: Fix imprecise external abort for
    pdmclk (bsc#1051510).

  - clk: dove: fix refcount leak in dove_clk_init()
    (bsc#1051510).

  - clk: highbank: fix refcount leak in hb_clk_init()
    (bsc#1051510).

  - clk: imx6q: fix refcount leak in imx6q_clocks_init()
    (bsc#1051510).

  - clk: imx6sl: ensure MMDC CH0 handshake is bypassed
    (bsc#1051510).

  - clk: imx6sx: fix refcount leak in imx6sx_clocks_init()
    (bsc#1051510).

  - clk: imx7d: fix refcount leak in imx7d_clocks_init()
    (bsc#1051510).

  - clk: ingenic: Fix doc of ingenic_cgu_div_info
    (bsc#1051510).

  - clk: ingenic: Fix round_rate misbehaving with
    non-integer dividers (bsc#1051510).

  - clk: kirkwood: fix refcount leak in kirkwood_clk_init()
    (bsc#1051510).

  - clk: mv98dx3236: fix refcount leak in
    mv98dx3236_clk_init() (bsc#1051510).

  - clk: qoriq: fix refcount leak in clockgen_init()
    (bsc#1051510).

  - clk: samsung: exynos4: fix refcount leak in
    exynos4_get_xom() (bsc#1051510).

  - clk: socfpga: fix refcount leak (bsc#1051510).

  - clk: sunxi: A31: Fix wrong AHB gate number
    (bsc#1051510).

  - clk: sunxi-ng: a33: Set CLK_SET_RATE_PARENT for all
    audio module clocks (bsc#1051510).

  - clk: sunxi-ng: sun8i-a23: Enable PLL-MIPI LDOs when
    ungating it (bsc#1051510).

  - clk: sunxi-ng: v3s: Fix TCON reset de-assert bit
    (bsc#1051510).

  - clk: uniphier: Fix update register for CPU-gear
    (bsc#1051510).

  - clk: vc5: Abort clock configuration without upstream
    clock (bsc#1051510).

  - clk: vf610: fix refcount leak in vf610_clocks_init()
    (bsc#1051510).

  - clocksource/drivers/exynos_mct: Clear timer interrupt
    when shutdown (bsc#1051510).

  - clocksource/drivers/exynos_mct: Fix error path in timer
    resources initialization (bsc#1051510).

  - clocksource/drivers/exynos_mct: Move one-shot check from
    tick clear to ISR (bsc#1051510).

  - clocksource/drivers/integrator-ap: Add missing
    of_node_put() (bsc#1051510).

  - clocksource/drivers/sun5i: Fail gracefully when clock
    rate is unavailable (bsc#1051510).

  - configfs: fix registered group removal (bsc#1051510).

  - copy_mount_string: Limit string length to PATH_MAX
    (bsc#1082943).

  - cpcap-charger: generate events for userspace
    (bsc#1051510).

  - cpufreq: Cap the default transition delay value to 10 ms
    (bsc#1127042).

  - cpufreq: conservative: Take limits changes into account
    properly (bsc#1051510).

  - cpufreq: governor: Avoid accessing invalid governor_data
    (bsc#1051510).

  - cpufreq: governor: Drop min_sampling_rate (bsc#1127042).

  - cpufreq: governor: Ensure sufficiently large sampling
    intervals (bsc#1127042).

  - cpufreq: pxa2xx: remove incorrect __init annotation
    (bsc#1051510).

  - cpufreq: tegra124: add missing of_node_put()
    (bsc#1051510).

  - cpufreq: Use transition_delay_us for legacy governors as
    well (bsc#1127042).

  - cpuidle: big.LITTLE: fix refcount leak (bsc#1051510).

  - crypto: aes_ti - disable interrupts while accessing
    S-box (bsc#1051510).

  - crypto: ahash - fix another early termination in hash
    walk (bsc#1051510).

  - crypto: arm64/aes-ccm - fix logical bug in AAD MAC
    handling (bsc#1051510).

  - crypto: arm/crct10dif - revert to C code for short
    inputs (bsc#1051510).

  - crypto: brcm - Fix some set-but-not-used warning
    (bsc#1051510).

  - crypto: caam - fixed handling of sg list (bsc#1051510).

  - crypto: cavium/zip - fix collision with generic
    cra_driver_name (bsc#1051510).

  - crypto: crypto4xx - add missing of_node_put after
    of_device_is_available (bsc#1051510).

  - crypto: crypto4xx - Fix wrong
    ppc4xx_trng_probe()/ppc4xx_trng_remove() arguments
    (bsc#1051510).

  - crypto: hash - set CRYPTO_TFM_NEED_KEY if ->setkey()
    fails (bsc#1051510).

  - crypto: testmgr - skip crc32c context test for ahash
    algorithms (bsc#1051510).

  - crypto: tgr192 - fix unaligned memory access
    (bsc#1051510).

  - crypto: ux500 - Use proper enum in cryp_set_dma_transfer
    (bsc#1051510).

  - crypto: ux500 - Use proper enum in hash_set_dma_transfer
    (bsc#1051510).

  - cw1200: drop useless LIST_HEAD (bsc#1051510).

  - cw1200: Fix concurrency use-after-free bugs in
    cw1200_hw_scan() (bsc#1051510).

  - cw1200: fix missing unlock on error in cw1200_hw_scan()
    (bsc#1051510).

  - dccp: fool proof ccid_hc_[rt]x_parse_options()
    (bsc#1051510).

  - debugfs: fix debugfs_rename parameter checking
    (bsc#1051510).

  - device property: Fix the length used in
    PROPERTY_ENTRY_STRING() (bsc#1051510).

  - dlm: Do not swamp the CPU with callbacks queued during
    recovery (bsc#1051510).

  - dmaengine: at_hdmac: drop useless LIST_HEAD
    (bsc#1051510).

  - dmaengine: at_xdmac: Fix wrongfull report of a channel
    as in use (bsc#1051510).

  - dmaengine: bcm2835: Fix abort of transactions
    (bsc#1051510).

  - dmaengine: bcm2835: Fix interrupt race on RT
    (bsc#1051510).

  - dmaengine: dmatest: Abort test in case of mapping error
    (bsc#1051510).

  - dmaengine: dw: drop useless LIST_HEAD (bsc#1051510).

  - dmaengine: imx-dma: fix wrong callback invoke
    (bsc#1051510).

  - dmaengine: mv_xor: Use correct device for DMA API
    (bsc#1051510).

  - dmaengine: pl330: drop useless LIST_HEAD (bsc#1051510).

  - dmaengine: sa11x0: drop useless LIST_HEAD (bsc#1051510).

  - dmaengine: st_fdma: drop useless LIST_HEAD
    (bsc#1051510).

  - dmaengine: stm32-dma: fix incomplete configuration in
    cyclic mode (bsc#1051510).

  - dma: Introduce dma_max_mapping_size() (bsc#1120008).

  - doc: rcu: Suspicious RCU usage is a warning
    (bsc#1051510).

  - Do not log confusing message on reconnect by default
    (bsc#1129664).

  - driver core: Do not resume suppliers under
    device_links_write_lock() (bsc#1051510).

  - drivers: hv: vmbus: Check for ring when getting debug
    info (bsc#1126389, bsc#1126579).

  - drivers: hv: vmbus: preserve hv_ringbuffer_get_debuginfo
    kABI (bsc#1126389, bsc#1126579).

  - drivers: hv: vmbus: Return -EINVAL for the sys files for
    unopened channels (bsc#1126389, bsc#1126579).

  - drm/amdgpu: Add delay after enable RLC ucode
    (bsc#1051510).

  - drm/ast: Fix connector leak during driver unload
    (bsc#1051510).

  - drm/ast: fixed reading monitor EDID not stable issue
    (bsc#1051510).

  - drm/atomic-helper: Complete fake_commit->flip_done
    potentially earlier (bsc#1051510).

  - drm: Block fb changes for async plane updates
    (bsc#1051510).

  - drm/bridge: tc358767: add defines for DP1_SRCCTRL &
    PHY_2LANE (bsc#1051510).

  - drm/bridge: tc358767: fix initial DP0/1_SRCCTRL value
    (bsc#1051510).

  - drm/bridge: tc358767: fix output H/V syncs
    (bsc#1051510).

  - drm/bridge: tc358767: fix single lane configuration
    (bsc#1051510).

  - drm/bridge: tc358767: reject modes which require too
    much BW (bsc#1051510).

  - drm/bufs: Fix Spectre v1 vulnerability (bsc#1051510).

  - drm: Clear state->acquire_ctx before leaving
    drm_atomic_helper_commit_duplicated_state()
    (bsc#1051510).

  - drm: disable uncached DMA optimization for ARM and arm64
    (bsc#1051510).

  - drm/etnaviv: NULL vs IS_ERR() buf in etnaviv_core_dump()
    (bsc#1113722)

  - drm/etnaviv: potential NULL dereference (bsc#1113722)

  - drm: Fix error handling in drm_legacy_addctx
    (bsc#1113722)

  - drm/i915/bios: assume eDP is present on port A when
    there is no VBT (bsc#1051510).

  - drm/i915: Block fbdev HPD processing during suspend
    (bsc#1113722)

  - drm/i915/fbdev: Actually configure untiled displays
    (bsc#1113722)

  - drm/i915: Flush GPU relocs harder for gen3 (bsc#1113722)

  - drm/i915/gvt: free VFIO region space in vgpu detach
    (bsc#1113722)

  - drm/i915/gvt: release shadow batch buffer and wa_ctx
    before destroy one workload (bsc#1051510).

  - drm/i915/opregion: fix version check (bsc#1113722)

  - drm/i915/opregion: rvda is relative from opregion base
    in opregion (bsc#1113722)

  - drm/i915: Prevent a race during I915_GEM_MMAP ioctl with
    WC set (bsc#1113722)

  - drm/i915: Redefine some Whiskey Lake SKUs (bsc#1051510).

  - drm/i915: Relax mmap VMA check (bsc#1051510).

  - drm/i915: Use the correct crtc when sanitizing plane
    mapping (bsc#1113722)

  - drm/imx: ignore plane updates on disabled crtcs
    (bsc#1051510).

  - drm/imx: imx-ldb: add missing of_node_puts
    (bsc#1051510).

  - drm/meson: add missing of_node_put (bsc#1051510).

  - drm/modes: Prevent division by zero htotal
    (bsc#1051510).

  - drm/msm: Fix error return checking (bsc#1051510).

  - drm/msm: Grab a vblank reference when waiting for
    commit_done (bsc#1051510).

  - drm/msm: Unblock writer if reader closes file
    (bsc#1051510).

  - drm/nouveau/bios/ramcfg: fix missing parentheses when
    calculating RON (bsc#1113722)

  - drm/nouveau/debugfs: Fix check of pm_runtime_get_sync
    failure (bsc#1051510).

  - drm/nouveau: Do not spew kernel WARNING for each timeout
    (bsc#1126480).

  - drm/nouveau: Do not WARN_ON VCPI allocation failures
    (bsc#1113722)

  - drm/nouveau/falcon: avoid touching registers if engine
    is off (bsc#1051510).

  - drm/nouveau/pmu: do not print reply values if exec is
    false (bsc#1113722)

  - drm/radeon/evergreen_cs: fix missing break in switch
    statement (bsc#1113722)

  - drm: Reorder set_property_atomic to avoid returning with
    an active ww_ctx (bsc#1051510).

  - drm/rockchip: fix for mailbox read size (bsc#1051510).

  - drm/shmob: Fix return value check in shmob_drm_probe
    (bsc#1113722)

  - drm/sun4i: tcon: Prepare and enable TCON channel 0 clock
    at init (bsc#1051510).

  - drm/vmwgfx: Do not double-free the mode stored in
    par->set_mode (bsc#1103429)

  - earlycon: Initialize port->uartclk based on
    clock-frequency property (bsc#1051510).

  - earlycon: Remove hardcoded port->uartclk initialization
    in of_setup_earlycon (bsc#1051510).

  - Enable CONFIG_RDMA_RXE=m also for ppc64le (bsc#1107665,)

  - Enable livepatch test drivers in lib/ Livepatch
    kselftests need those.

  - enic: fix build warning without CONFIG_CPUMASK_OFFSTACK
    (bsc#1051510).

  - enic: fix checksum validation for IPv6 (bsc#1051510).

  - esp6: fix memleak on error path in esp6_input
    (bsc#1051510).

  - esp: Fix locking on page fragment allocation
    (bsc#1051510).

  - esp: Fix memleaks on error paths (bsc#1051510).

  - esp: Fix skb tailroom calculation (bsc#1051510).

  - ext4: avoid kernel warning when writing the superblock
    to a dead device (bsc#1124981).

  - ext4: Avoid panic during forced reboot (bsc#1126356).

  - ext4: check for shutdown and r/o file system in
    ext4_write_inode() (bsc#1124978).

  - ext4: fix a potential fiemap/page fault deadlock w/
    inline_data (bsc#1124980).

  - ext4: force inode writes when nfsd calls
    commit_metadata() (bsc#1125125).

  - ext4: include terminating u32 in size of xattr entries
    when expanding inodes (bsc#1124976).

  - ext4: make sure enough credits are reserved for
    dioread_nolock writes (bsc#1124979).

  - ext4: track writeback errors using the generic tracking
    infrastructure (bsc#1124982).

  - fbdev: chipsfb: remove set but not used variable 'size'
    (bsc#1113722)

  - firmware/efi: Add NULL pointer checks in efivars API
    functions (bsc#1051510).

  - floppy: check_events callback should not return a
    negative number (bsc#1051510).

  - fs/dax: deposit pagetable even when installing zero page
    (bsc#1126740).

  - fs/dcache: Fix incorrect nr_dentry_unused accounting in
    shrink_dcache_sb() (git-fixes).

  - fs/devpts: always delete dcache dentry-s in dput()
    (git-fixes).

  - fuse: call pipe_buf_release() under pipe lock
    (bsc#1051510).

  - fuse: continue to send FUSE_RELEASEDIR when FUSE_OPEN
    returns ENOSYS (bsc#1051510).

  - fuse: decrement NR_WRITEBACK_TEMP on the right page
    (bsc#1051510).

  - fuse: handle zero sized retrieve correctly
    (bsc#1051510).

  - futex: Fix (possible) missed wakeup (bsc#1050549).

  - gdrom: fix a memory leak bug (bsc#1051510).

  - geneve: cleanup hard coded value for Ethernet header
    length (bsc#1123456).

  - geneve: correctly handle ipv6.disable module parameter
    (bsc#1051510).

  - geneve, vxlan: Do not check skb_dst() twice
    (bsc#1123456).

  - geneve, vxlan: Do not set exceptions if skb->len < mtu
    (bsc#1123456).

  - genwqe: Fix size check (bsc#1051510).

  - gfs2: Revert 'Fix loop in gfs2_rbm_find' (bsc#1120601).

  - gianfar: fix a flooded alignment reports because of
    padding issue (bsc#1051510).

  - gianfar: Fix Rx byte accounting for ndev stats
    (bsc#1051510).

  - gianfar: prevent integer wrapping in the rx handler
    (bsc#1051510).

  - gpu: ipu-v3: Fix CSI offsets for imx53 (bsc#1113722)

  - gpu: ipu-v3: Fix i.MX51 CSI control registers offset
    (bsc#1113722)

  - gpu: ipu-v3: image-convert: Prevent race between run and
    unprepare (bsc#1051510).

  - gro_cells: make sure device is up in gro_cells_receive()
    (git-fixes).

  - hid: lenovo: Add checks to fix of_led_classdev_register
    (bsc#1051510).

  - hpet: Fix missing '=' character in the __setup() code of
    hpet_mmap_enable (git-fixes).

  - hvc_opal: do not set tb_ticks_per_usec in
    udbg_init_opal_common() (bsc#1051510).

  - hv: reduce storvsc_ringbuffer_size from 1M to 128K to
    simplify booting with 1k vcpus ().

  - hv: v4.12 API for hyperv-iommu (bsc#1122822).

  - hwmon: (lm80) fix a missing check of bus read in lm80
    probe (bsc#1051510).

  - hwmon: (lm80) fix a missing check of the status of SMBus
    read (bsc#1051510).

  - hwmon: (lm80) Fix missing unlock on error in
    set_fan_div() (bsc#1051510).

  - hwmon: (tmp421) Correct the misspelling of the tmp442
    compatible attribute in OF device ID table
    (bsc#1051510).

  - HYPERV/IOMMU: Add Hyper-V stub IOMMU driver
    (bsc#1122822).

  - i2c-axxia: check for error conditions first
    (bsc#1051510).

  - i2c: bcm2835: Clear current buffer pointers and counts
    after a transfer (bsc#1051510).

  - i2c: cadence: Fix the hold bit setting (bsc#1051510).

  - i2c: omap: Use noirq system sleep pm ops to idle device
    for suspend (bsc#1051510).

  - i2c: sh_mobile: add support for r8a77990 (R-Car E3)
    (bsc#1051510).

  - i2c: tegra: fix maximum transfer size (bsc#1051510).

  - ib/core: Destroy QP if XRC QP fails (bsc#1046306).

  - ib/core: Fix potential memory leak while creating MAD
    agents (bsc#1046306).

  - ib/core: Unregister notifier before freeing MAD security
    (bsc#1046306).

  - ib/hfi1: Close race condition on user context disable
    and close (bsc#1060463).

  - ib/mlx5: Unmap DMA addr from HCA before IOMMU
    (bsc#1046305 ).

  - ibmvnic: Report actual backing device speed and duplex
    values (bsc#1129923).

  - ibmvscsi: Fix empty event pool access during host
    removal (bsc#1119019).

  - ibmvscsi: Protect ibmvscsi_head from concurrent
    modificaiton (bsc#1119019).

  - ieee802154: ca8210: fix possible u8 overflow in
    ca8210_rx_done (bsc#1051510).

  - igb: Fix an issue that PME is not enabled during runtime
    suspend (bsc#1051510).

  - iio: accel: kxcjk1013: Add KIOX010A ACPI Hardware-ID
    (bsc#1051510).

  - iio: adc: exynos-adc: Fix NULL pointer exception on
    unbind (bsc#1051510).

  - iio: chemical: atlas-ph-sensor: correct IIO_TEMP values
    to millicelsius (bsc#1051510).

  - Input: bma150 - register input device after setting
    private data (bsc#1051510).

  - input: cap11xx - switch to using
    set_brightness_blocking() (bsc#1051510).

  - Input: elan_i2c - add ACPI ID for touchpad in Lenovo
    V330-15ISK (bsc#1051510).

  - Input: elan_i2c - add id for touchpad found in Lenovo
    s21e-20 (bsc#1051510).

  - Input: elantech - enable 3rd button support on Fujitsu
    CELSIUS H780 (bsc#1051510).

  - input: matrix_keypad - use flush_delayed_work()
    (bsc#1051510).

  - Input: raspberrypi-ts - select CONFIG_INPUT_POLLDEV
    (git-fixes).

  - input: st-keyscan - fix potential zalloc NULL
    dereference (bsc#1051510).

  - input: uinput - fix undefined behavior in
    uinput_validate_absinfo() (bsc#1120902).

  - Input: wacom_serial4 - add support for Wacom ArtPad II
    tablet (bsc#1051510).

  - intel_th: Do not reference unassigned outputs
    (bsc#1051510).

  - intel_th: gth: Fix an off-by-one in output unassigning
    (bsc#1051510).

  - iomap: fix integer truncation issues in the zeroing and
    dirtying helpers (bsc#1125947).

  - iomap: warn on zero-length mappings (bsc#1127062).

  - iommu/amd: Fix NULL dereference bug in match_hid_uid
    (bsc#1130336).

  - iommu/amd: fix sg->dma_address for sg->offset bigger
    than PAGE_SIZE (bsc#1130337).

  - iommu/amd: Reserve exclusion range in iova-domain
    (bsc#1130425).

  - iommu/dmar: Fix buffer overflow during PCI bus
    notification (bsc#1129181).

  - iommu: Document iommu_ops.is_attach_deferred()
    (bsc#1129182).

  - iommu: Do not print warning when IOMMU driver only
    supports unmanaged domains (bsc#1130130).

  - iommu/io-pgtable-arm-v7s: Only kmemleak_ignore L2 tables
    (bsc#1129205).

  - iommu/vt-d: Check capability before disabling protected
    memory (bsc#1130338).

  - iommu/vt-d: Check identity map for hot-added devices
    (bsc#1129183).

  - iommu/vt-d: Fix NULL pointer reference in
    intel_svm_bind_mm() (bsc#1129184).

  - ip6: fix PMTU discovery when using /127 subnets
    (git-fixes).

  - ip6mr: Do not call __IP6_INC_STATS() from preemptible
    context (git-fixes).

  - ip6_tunnel: get the min mtu properly in ip6_tnl_xmit
    (bsc#1123456).

  - ip6_tunnel: use the right value for ipv4 min mtu check
    in ip6_tnl_xmit (bsc#1123456).

  - ipsec: check return value of skb_to_sgvec always
    (bsc#1051510).

  - ipv4/route: fail early when inet dev is missing
    (git-fixes).

  - ipv4: speedup ipv6 tunnels dismantle (bsc#1122982).

  - ipv6: addrlabel: per netns list (bsc#1122982).

  - ipv6: Consider sk_bound_dev_if when binding a socket to
    an address (networking-stable-19_02_01).

  - ipv6: Consider sk_bound_dev_if when binding a socket to
    a v4 mapped address (networking-stable-19_01_22).

  - ipv6: fix kernel-infoleak in ipv6_local_error()
    (networking-stable-19_01_20).

  - ipv6: speedup ipv6 tunnels dismantle (bsc#1122982).
    Refresh
    patches.suse/ip6_vti-fix-a-null-pointer-deference-when-d
    estroy-vt.patch

  - ipv6: Take rcu_read_lock in __inet6_bind for mapped
    addresses (networking-stable-19_01_22).

  - ipvlan, l3mdev: fix broken l3s mode wrt local routes
    (networking-stable-19_02_01).

  - irqchip/gic-v3-its: Align PCI Multi-MSI allocation on
    their size (bsc#1051510).

  - irqchip/gic-v3-its: Avoid parsing _indirect_ twice for
    Device table (bsc#1051510).

  - irqchip/gic-v3-its: Do not bind LPI to unavailable NUMA
    node (bsc#1051510).

  - irqchip/gic-v3-its: Fix ITT_entry_size accessor
    (bsc#1051510).

  - irqchip/mmp: Only touch the PJ4 IRQ & FIQ bits on
    enable/disable (bsc#1051510).

  - iscsi_ibft: Fix missing break in switch statement
    (bsc#1051510).

  - isdn: avm: Fix string plus integer warning from Clang
    (bsc#1051510).

  - isdn: hisax: hfc_pci: Fix a possible concurrency
    use-after-free bug in HFCPCI_l1hw() (bsc#1051510).

  - isdn: i4l: isdn_tty: Fix some concurrency double-free
    bugs (bsc#1051510).

  - iser: set sector for ambiguous mr status errors
    (bsc#1051510).

  - iwlwifi: mvm: avoid possible access out of array
    (bsc#1051510).

  - iwlwifi: mvm: fix A-MPDU reference assignment
    (bsc#1051510).

  - iwlwifi: mvm: fix firmware statistics usage
    (bsc#1129770).

  - iwlwifi: mvm: fix RSS config command (bsc#1051510).

  - iwlwifi: pcie: fix emergency path (bsc#1051510).

  - iwlwifi: pcie: fix TX while flushing (bsc#1120902).

  - ixgbe: Be more careful when modifying MAC filters
    (bsc#1051510).

  - ixgbe: check return value of napi_complete_done()
    (bsc#1051510).

  - ixgbe: recognize 1000BaseLX SFP modules as 1Gbps
    (bsc#1051510).

  - kabi: cpufreq: keep min_sampling_rate in struct dbs_data
    (bsc#1127042).

  - kabi: handle addition of ip6addrlbl_table into struct
    netns_ipv6 (bsc#1122982).

  - kabi: handle addition of uevent_sock into struct net
    (bsc#1122982).

  - kabi: Preserve kABI for dma_max_mapping_size()
    (bsc#1120008).

  - kabi: protect vhost_log_write (kabi).

  - kabi: restore ip_tunnel_delete_net() (bsc#1122982).

  - kabi workaround for ath9k ath_node.ackto type change
    (bsc#1051510).

  - kABI workaround for bt_accept_enqueue() change
    (bsc#1051510).

  - kallsyms: Handle too long symbols in kallsyms.c
    (bsc#1126805).

  - kasan: fix shadow_size calculation error in
    kasan_module_alloc (bsc#1051510).

  - kbuild: fix false positive warning/error about missing
    libelf (bsc#1051510).

  - kconfig: fix file name and line number of
    warn_ignored_character() (bsc#1051510).

  - kconfig: fix line numbers for if-entries in menu tree
    (bsc#1051510).

  - kconfig: fix memory leak when EOF is encountered in
    quotation (bsc#1051510).

  - kconfig: fix the rule of mainmenu_stmt symbol
    (bsc#1051510).

  - keys: allow reaching the keys quotas exactly
    (bsc#1051510).

  - keys: Timestamp new keys (bsc#1051510).

  - kgdboc: fix KASAN global-out-of-bounds bug in
    param_set_kgdboc_var() (bsc#1051510).

  - kgdboc: Fix restrict error (bsc#1051510).

  - kgdboc: Fix warning with module build (bsc#1051510).

  - kobject: add kobject_uevent_net_broadcast()
    (bsc#1122982).

  - kobject: copy env blob in one go (bsc#1122982).

  - kobject: factorize skb setup in
    kobject_uevent_net_broadcast() (bsc#1122982).

  - kprobes: Return error if we fail to reuse kprobe instead
    of BUG_ON() (bsc#1051510).

  - kvm: mmu: Fix race in emulated page table writes
    (bsc#1129284).

  - kvm: nVMX: Free the VMREAD/VMWRITE bitmaps if
    alloc_kvm_area() fails (bsc#1129291).

  - kvm: nVMX: NMI-window and interrupt-window exiting
    should wake L2 from HLT (bsc#1129292).

  - kvm: nVMX: Set VM instruction error for VMPTRLD of
    unbacked page (bsc#1129293).

  - kvm: vmx: Set IA32_TSC_AUX for legacy mode guests
    (bsc#1129294).

  - kvm: x86: Add AMD's EX_CFG to the list of ignored MSRs
    (bsc#1127082).

  - kvm: x86: Fix single-step debugging (bsc#1129295).

  - kvm: x86: Use jmp to invoke kvm_spurious_fault() from
    .fixup (bsc#1129296).

  - l2tp: copy 4 more bytes to linear part if necessary
    (networking-stable-19_02_01).

  - l2tp: fix infoleak in l2tp_ip6_recvmsg() (git-fixes).

  - l2tp: fix reading optional fields of L2TPv3
    (networking-stable-19_02_01).

  - leds: lp5523: fix a missing check of return value of
    lp55xx_read (bsc#1051510).

  - leds: lp55xx: fix null deref on firmware load failure
    (bsc#1051510).

  - libceph: avoid KEEPALIVE_PENDING races in
    ceph_con_keepalive() (bsc#1125800).

  - libceph: handle an empty authorize reply (bsc#1126789).

  - libceph: wait for latest osdmap in
    ceph_monc_blacklist_add() (bsc#1130427).

  - lib/div64.c: off by one in shift (bsc#1051510).

  - libertas_tf: do not set URB_ZERO_PACKET on IN USB
    transfer (bsc#1051510).

  - libnvdimm: Fix altmap reservation size calculation
    (bsc#1127682).

  - libnvdimm/label: Clear 'updating' flag after label-set
    update (bsc#1129543).

  - libnvdimm/pmem: Honor force_raw for legacy pmem regions
    (bsc#1129551).

  - lightnvm: fail fast on passthrough commands
    (bsc#1125780).

  - livepatch: Change unsigned long old_addr -> void
    *old_func in struct klp_func (bsc#1071995).

  - livepatch: Consolidate klp_free functions (bsc#1071995
    ).

  - livepatch: core: Return EOPNOTSUPP instead of ENOSYS
    (bsc#1071995).

  - livepatch: Define a macro for new API identification
    (bsc#1071995).

  - livepatch: Do not block the removal of patches loaded
    after a forced transition (bsc#1071995).

  - livepatch: Introduce klp_for_each_patch macro
    (bsc#1071995 ).

  - livepatch: Module coming and going callbacks can proceed
    with all listed patches (bsc#1071995).

  - livepatch: Proper error handling in the shadow variables
    selftest (bsc#1071995).

  - livepatch: Remove ordering (stacking) of the livepatches
    (bsc#1071995).

  - livepatch: Remove signal sysfs attribute (bsc#1071995 ).

  - livepatch: return -ENOMEM on ptr_id() allocation failure
    (bsc#1071995).

  - livepatch: Send a fake signal periodically (bsc#1071995
    ).

  - livepatch: Shuffle
    klp_enable_patch()/klp_disable_patch() code
    (bsc#1071995).

  - livepatch: Simplify API by removing registration step
    (bsc#1071995).

  - llc: do not use sk_eat_skb() (bsc#1051510).

  - locking/rwsem: Fix (possible) missed wakeup
    (bsc#1050549).

  - loop: drop caches if offset or block_size are changed
    (bsc#1124975).

  - loop: Reintroduce lo_ctl_mutex removed by commit
    310ca162d (bsc#1124974).

  - mac80211: Add attribute aligned(2) to struct 'action'
    (bsc#1051510).

  - mac80211: do not initiate TDLS connection if station is
    not associated to AP (bsc#1051510).

  - mac80211: ensure that mgmt tx skbs have tailroom for
    encryption (bsc#1051510).

  - mac80211: fix miscounting of ttl-dropped frames
    (bsc#1051510).

  - mac80211: fix radiotap vendor presence bitmap handling
    (bsc#1051510).

  - mac80211: Fix Tx aggregation session tear down with
    ITXQs (bsc#1051510).

  - mac80211: Free mpath object when rhashtable insertion
    fails (bsc#1051510).

  - mac80211_hwsim: propagate genlmsg_reply return code
    (bsc#1051510).

  - mac80211: Restore vif beacon interval if start ap fails
    (bsc#1051510).

  - macvlan: Only deliver one copy of the frame to the
    macvlan interface (bsc#1051510).

  - mailbox: bcm-flexrm-mailbox: Fix FlexRM ring flush
    timeout issue (bsc#1051510).

  - mdio_bus: Fix use-after-free on device_register fails
    (bsc#1051510).

  - media: adv*/tc358743/ths8200: fill in min
    width/height/pixelclock (bsc#1051510).

  - media: DaVinci-VPBE: fix error handling in
    vpbe_initialize() (bsc#1051510).

  - media: dt-bindings: media: i2c: Fix i2c address for
    OV5645 camera sensor (bsc#1051510).

  - media: mtk-vcodec: Release device nodes in
    mtk_vcodec_init_enc_pm() (bsc#1051510).

  - media: rc: mce_kbd decoder: fix stuck keys
    (bsc#1100132).

  - media: s5k4ecgx: delete a bogus error message
    (bsc#1051510).

  - media: s5p-jpeg: Check for fmt_ver_flag when doing fmt
    enumeration (bsc#1051510).

  - media: s5p-jpeg: Correct step and max values for
    V4L2_CID_JPEG_RESTART_INTERVAL (bsc#1051510).

  - media: s5p-mfc: fix incorrect bus assignment in virtual
    child device (bsc#1051510).

  - media: uvcvideo: Avoid NULL pointer dereference at the
    end of streaming (bsc#1051510).

  - media: uvcvideo: Fix 'type' check leading to overflow
    (bsc#1051510).

  - media: v4l2-ctrls.c/uvc: zero v4l2_event (bsc#1051510).

  - media: v4l2: i2c: ov7670: Fix PLL bypass register values
    (bsc#1051510).

  - media: vb2: do not call __vb2_queue_cancel if
    vb2_start_streaming failed (bsc#1119086).

  - memremap: fix softlockup reports at teardown
    (bnc#1130154).

  - memstick: Prevent memstick host from getting runtime
    suspended during card detection (bsc#1051510).

  - mfd: db8500-prcmu: Fix some section annotations
    (bsc#1051510).

  - mfd: mc13xxx: Fix a missing check of a register-read
    failure (bsc#1051510).

  - mfd: mt6397: Do not call irq_domain_remove if PMIC
    unsupported (bsc#1051510).

  - mfd: qcom_rpm: write fw_version to CTRL_REG
    (bsc#1051510).

  - mfd: ti_am335x_tscadc: Use PLATFORM_DEVID_AUTO while
    registering mfd cells (bsc#1051510).

  - mfd: tps65218: Use devm_regmap_add_irq_chip and clean up
    error path in probe() (bsc#1051510).

  - mfd: twl-core: Fix section annotations on
    {,un}protect_pm_master (bsc#1051510).

  - mfd: wm5110: Add missing ASRC rate register
    (bsc#1051510).

  - misc: hpilo: Do not claim unsupported hardware
    (bsc#1129330).

  - misc: hpilo: Exclude unsupported device via blacklist
    (bsc#1129330).

  - mISDN: fix a race in dev_expire_timer() (bsc#1051510).

  - mlxsw: __mlxsw_sp_port_headroom_set(): Fix a use of
    local variable (git-fixes).

  - mlxsw: spectrum: Disable lag port TX before removing it
    (networking-stable-19_01_22).

  - mmap: introduce sane default mmap limits (git fixes
    (mm/mmap)).

  - mmap: relax file size limit for regular files (git fixes
    (mm/mmap)).

  - mmc: bcm2835: Recover from MMC_SEND_EXT_CSD
    (bsc#1051510).

  - mmc: Kconfig: Enable CONFIG_MMC_SDHCI_IO_ACCESSORS
    (bsc#1051510).

  - mmc: omap: fix the maximum timeout setting
    (bsc#1051510).

  - mmc: pxamci: fix enum type confusion (bsc#1051510).

  - mmc: sdhci-brcmstb: handle mmc_of_parse() errors during
    probe (bsc#1051510).

  - mmc: sdhci-esdhc-imx: fix HS400 timing issue
    (bsc#1051510).

  - mmc: sdhci-of-esdhc: Fix timeout checks (bsc#1051510).

  - mmc: sdhci-xenon: Fix timeout checks (bsc#1051510).

  - mmc: spi: Fix card detection during probe (bsc#1051510).

  - mm: do not drop unused pages when userfaultd is running
    (git fixes (mm/userfaultfd)).

  - mm: Fix modifying of page protection by insert_pfn()
    (bsc#1126740).

  - mm: Fix warning in insert_pfn() (bsc#1126740).

  - mm/hmm: hmm_pfns_bad() was accessing wrong struct (git
    fixes (mm/hmm)).

  - mm: hwpoison: use do_send_sig_info() instead of
    force_sig() (git fixes (mm/hwpoison)).

  - mm/ksm.c: ignore STABLE_FLAG of rmap_item->address in
    rmap_walk_ksm() (git fixes (mm/ksm)).

  - mm: madvise(MADV_DODUMP): allow hugetlbfs pages (git
    fixes (mm/madvise)).

  - mm,memory_hotplug: fix scan_movable_pages() for gigantic
    hugepages (bsc#1127731).

  - mm: migrate: do not rely on __PageMovable() of newpage
    after unlocking it (git fixes (mm/migrate)).

  - mm, oom: fix use-after-free in oom_kill_process (git
    fixes (mm/oom)).

  - mm: use swp_offset as key in shmem_replace_page() (git
    fixes (mm/shmem)).

  - mm,vmscan: Make unregister_shrinker() no-op if
    register_shrinker() failed (git fixes (mm/vmscan)).

  - Move upstreamed ALSA and BT patches into sorted section

  - Move upstreamed libnvdimm patch into sorted section

  - mtd: cfi_cmdset_0002: Avoid walking all chips when
    unlocking (bsc#1051510).

  - mtd: cfi_cmdset_0002: Change write buffer to check
    correct value (bsc#1051510).

  - mtd: cfi_cmdset_0002: fix SEGV unlocking multiple chips
    (bsc#1051510).

  - mtd: cfi_cmdset_0002: Fix unlocking requests crossing a
    chip boudary (bsc#1051510).

  - mtd: cfi_cmdset_0002: Use right chip in do_ppb_xxlock()
    (bsc#1051510).

  - mtdchar: fix overflows in adjustment of `count`
    (bsc#1051510).

  - mtdchar: fix usage of mtd_ooblayout_ecc() (bsc#1051510).

  - mtd: docg3: do not set conflicting BCH_CONST_PARAMS
    option (bsc#1051510).

  - mtd/maps: fix solutionengine.c printk format warnings
    (bsc#1051510).

  - mtd: mtd_oobtest: Handle bitflips during reads
    (bsc#1051510).

  - mtd: nand: atmel: fix buffer overflow in
    atmel_pmecc_user (bsc#1051510).

  - mtd: nand: atmel: Fix get_sectorsize() function
    (bsc#1051510).

  - mtd: nand: atmel: fix of_irq_get() error check
    (bsc#1051510).

  - mtd: nand: brcmnand: Disable prefetch by default
    (bsc#1051510).

  - mtd: nand: brcmnand: Zero bitflip is not an error
    (bsc#1051510).

  - mtd: nand: denali_pci: add missing
    MODULE_DESCRIPTION/AUTHOR/LICENSE (bsc#1051510).

  - mtd: nand: fix interpretation of NAND_CMD_NONE in
    nand_command[_lp]() (bsc#1051510).

  - mtd: nand: Fix nand_do_read_oob() return value
    (bsc#1051510).

  - mtd: nand: Fix writing mtdoops to nand flash
    (bsc#1051510).

  - mtd: nand: fsl_ifc: Fix nand waitfunc return value
    (bsc#1051510).

  - mtd: nand: gpmi: Fix failure when a erased page has a
    bitflip at BBM (bsc#1051510).

  - mtd: nand: ifc: update bufnum mask for ver >= 2.0.0
    (bsc#1051510).

  - mtd: nand: mtk: fix infinite ECC decode IRQ issue
    (bsc#1051510).

  - mtd: nand: omap2: Fix subpage write (bsc#1051510).

  - mtd: nand: pxa3xx: Fix READOOB implementation
    (bsc#1051510).

  - mtd: nand: qcom: Add a NULL check for devm_kasprintf()
    (bsc#1051510).

  - mtd: nandsim: remove debugfs entries in error path
    (bsc#1051510).

  - mtd: nand: sunxi: Fix ECC strength choice (bsc#1051510).

  - mtd: nand: sunxi: fix potential divide-by-zero error
    (bsc#1051510).

  - mtd: nand: vf610: set correct ooblayout (bsc#1051510).

  - mtd: spi-nor: cadence-quadspi: Fix page fault kernel
    panic (bsc#1051510).

  - mtd: spi-nor: Fix Cadence QSPI page fault kernel panic
    (bsc#1051510).

  - mtd: spi-nor: fsl-quadspi: fix read error for flash size
    larger than 16MB (bsc#1051510).

  - mtd: spi-nor: stm32-quadspi: Fix uninitialized error
    return code (bsc#1051510).

  - mv88e6060: disable hardware level MAC learning
    (bsc#1051510).

  - nbd: Use set_blocksize() to set device blocksize
    (bsc#1124984).

  - net: add uevent socket member (bsc#1122982).

  - net: aquantia: driver should correctly declare
    vlan_features bits (bsc#1051510).

  - net: aquantia: fixed instack structure overflow
    (git-fixes).

  - net: aquantia: Fix hardware DMA stream overload on large
    MRRS (bsc#1051510).

  - net: bcmgenet: abort suspend on error (bsc#1051510).

  - net: bcmgenet: code movement (bsc#1051510).

  - net: bcmgenet: fix OF child-node lookup (bsc#1051510).

  - net: bcmgenet: remove HFB_CTRL access (bsc#1051510).

  - net: bcmgenet: return correct value 'ret' from
    bcmgenet_power_down (bsc#1051510).

  - net: bridge: fix a bug on using a neighbour cache entry
    without checking its state (networking-stable-19_01_20).

  - net: bridge: Fix ethernet header pointer before check
    skb forwardable (networking-stable-19_01_26).

  - net: do not call update_pmtu unconditionally
    (bsc#1123456).

  - net: Do not default Cavium PTP driver to 'y'
    (bsc#1110096).

  - net: dp83640: expire old TX-skb
    (networking-stable-19_02_10).

  - net: dsa: mv88e6xxx: handle unknown duplex modes
    gracefully in mv88e6xxx_port_set_duplex (git-fixes).

  - net: dsa: mv88x6xxx: mv88e6390 errata
    (networking-stable-19_01_22).

  - net: dsa: slave: Do not propagate flag changes on down
    slave interfaces (networking-stable-19_02_10).

  - net: ena: fix race between link up and device
    initalization (bsc#1083548).

  - net: ena: update driver version from 2.0.2 to 2.0.3
    (bsc#1129276 bsc#1125342).

  - netfilter: check for seqadj ext existence before adding
    it in nf_nat_setup_info (git-fixes).

  - netfilter: nf_tables: check the result of dereferencing
    base_chain->stats (git-fixes).

  - net: Fix usage of pskb_trim_rcsum
    (networking-stable-19_01_26).

  - net: ipv4: Fix memory leak in network namespace
    dismantle (networking-stable-19_01_26).

  - net/mlx4_core: Add masking for a few queries on HCA caps
    (networking-stable-19_02_01).

  - net/mlx4_core: Fix locking in SRIOV mode when switching
    between events and polling (git-fixes).

  - net/mlx4_core: Fix qp mtt size calculation (git-fixes).

  - net/mlx4_core: Fix reset flow when in command polling
    mode (git-fixes).

  - net/mlx5e: Allow MAC invalidation while spoofchk is ON
    (networking-stable-19_02_01).

  - net/mlx5e: IPoIB, Fix RX checksum statistics update
    (git-fixes).

  - net/mlx5e: RX, Fix wrong early return in receive queue
    poll (bsc#1046305).

  - net/mlx5: fix uaccess beyond 'count' in debugfs
    read/write handlers (git-fixes).

  - net/mlx5: Release resource on error flow (git-fixes).

  - net/mlx5: Return success for PAGE_FAULT_RESUME in
    internal error state (git-fixes).

  - net/mlx5: Use multi threaded workqueue for page fault
    handling (git-fixes).

  - net/ncsi: Fix AEN HNCDSC packet length (git-fixes).

  - net/ncsi: Stop monitor if channel times out or is
    inactive (git-fixes).

  - net: netem: fix skb length BUG_ON in __skb_to_sgvec
    (git-fixes).

  - netns: restrict uevents (bsc#1122982).

  - net: phy: marvell: Errata for mv88e6390 internal PHYs
    (networking-stable-19_01_26).

  - net: phy: mdio_bus: add missing device_del() in
    mdiobus_register() error handling
    (networking-stable-19_01_26).

  - net: phy: Micrel KSZ8061: link failure after cable
    connect (git-fixes).

  - netrom: switch to sock timer API (bsc#1051510).

  - net/rose: fix NULL ax25_cb kernel panic
    (networking-stable-19_02_01).

  - net/sched: act_tunnel_key: fix memory leak in case of
    action replace (networking-stable-19_01_26).

  - net_sched: refetch skb protocol for each filter
    (networking-stable-19_01_26).

  - net: set default network namespace in
    init_dummy_netdev() (networking-stable-19_02_01).

  - net: stmmac: Fix a race in EEE enable callback
    (git-fixes).

  - net: stmmac: fix broken dma_interrupt handling for
    multi-queues (git-fixes).

  - net: stmmac: handle endianness in dwmac4_get_timestamp
    (git-fixes).

  - net: stmmac: Use mutex instead of spinlock (git-fixes).

  - net-sysfs: Fix mem leak in netdev_register_kobject
    (git-fixes).

  - net: systemport: Fix WoL with password after deep sleep
    (networking-stable-19_02_10).

  - net: thunderx: fix NULL pointer dereference in
    nic_remove (git-fixes).

  - nfit: acpi_nfit_ctl(): Check out_obj->type in the right
    place (bsc#1129547).

  - nfit/ars: Attempt a short-ARS whenever the ARS state is
    idle at boot (bsc#1051510).

  - nfit/ars: Attempt short-ARS even in the no_init_ars case
    (bsc#1051510).

  - nfp: bpf: fix ALU32 high bits clearance bug (git-fixes).

  - nfsd: fix memory corruption caused by readdir
    (bsc#1127445).

  - niu: fix missing checks of niu_pci_eeprom_read
    (bsc#1051510).

  - ntb_transport: Fix bug with max_mw_size parameter
    (bsc#1051510).

  - nvme-fc: reject reconnect if io queue count is reduced
    to zero (bsc#1128351).

  - nvme: flush namespace scanning work just before removing
    namespaces (bsc#1108101).

  - nvme: kABI fix for scan_lock (bsc#1123882).

  - nvme: lock NS list changes while handling command
    effects (bsc#1123882).

  - nvme-loop: fix kernel oops in case of unhandled command
    (bsc#1126807).

  - nvme-multipath: drop optimization for static ANA group
    IDs (bsc#1113939).

  - nvme-pci: fix out of bounds access in nvme_cqe_pending
    (bsc#1127595).

  - nvme: schedule requeue whenever a LIVE state is entered
    (bsc#1123105).

  - of, numa: Validate some distance map rules
    (bsc#1051510).

  - of: unittest: Disable interrupt node tests for old world
    MAC systems (bsc#1051510).

  - openvswitch: Avoid OOB read when parsing flow nlattrs
    (bsc#1051510).

  - openvswitch: fix the incorrect flow action alloc size
    (bsc#1051510).

  - openvswitch: Remove padding from packet before L3+
    conntrack processing (bsc#1051510).

  - parport_pc: fix find_superio io compare code, should use
    equal test (bsc#1051510).

  - Partially revert 'block: fail op_is_write() requests to
    (bsc#1125252).

  - pci: add USR vendor id and use it in r8169 and w6692
    driver (networking-stable-19_01_22).

  - pci: designware-ep: dw_pcie_ep_set_msi() should only set
    MMC bits (bsc#1051510).

  - pci: endpoint: functions: Use
    memcpy_fromio()/memcpy_toio() (bsc#1051510).

  - pci-hyperv: increase HV_VP_SET_BANK_COUNT_MAX to handle
    1792 vcpus (bsc#1122822).

  - pci/pme: Fix hotplug/sysfs remove deadlock in
    pcie_pme_remove() (bsc#1051510).

  - pci: qcom: Do not deassert reset GPIO during probe
    (bsc#1129281).

  - pcrypt: use format specifier in kobject_add
    (bsc#1051510).

  - perf/x86: Add sysfs entry to freeze counters on SMI
    (bsc#1121805).

  - perf/x86/intel: Delay memory deallocation until
    x86_pmu_dead_cpu() (bsc#1121805).

  - perf/x86/intel: Do not enable freeze-on-smi for PerfMon
    V1 (bsc#1121805).

  - perf/x86/intel: Fix memory corruption (bsc#1121805).

  - perf/x86/intel: Generalize dynamic constraint creation
    (bsc#1121805).

  - perf/x86/intel: Implement support for TSX Force Abort
    (bsc#1121805).

  - perf/x86/intel: Make cpuc allocations consistent
    (bsc#1121805).

  - phy: allwinner: sun4i-usb: poll vbus changes on A23/A33
    when driving VBUS (bsc#1051510).

  - phy: qcom-qmp: Fix failure path in phy_init functions
    (bsc#1051510).

  - phy: qcom-qmp: Fix phy pipe clock gating (bsc#1051510).

  - phy: renesas: rcar-gen3-usb2: fix vbus_ctrl for role
    sysfs (bsc#1051510).

  - phy: rockchip-emmc: retry calpad busy trimming
    (bsc#1051510).

  - phy: sun4i-usb: add support for missing USB PHY index
    (bsc#1051510).

  - phy: tegra: remove redundant self assignment of 'map'
    (bsc#1051510).

  - phy: work around 'phys' references to usb-nop-xceiv
    devices (bsc#1051510).

  - pinctrl: max77620: Use define directive for
    max77620_pinconf_param values (bsc#1051510).

  - pinctrl: meson: fix pull enable register calculation
    (bsc#1051510).

  - pinctrl: meson: meson8b: fix the GPIO function for the
    GPIOAO pins (bsc#1051510).

  - pinctrl: meson: meson8b: fix the sdxc_a data 1..3 pins
    (bsc#1051510).

  - pinctrl: meson: meson8: fix the GPIO function for the
    GPIOAO pins (bsc#1051510).

  - pinctrl: msm: fix gpio-hog related boot issues
    (bsc#1051510).

  - pinctrl: sh-pfc: emev2: Add missing pinmux functions
    (bsc#1051510).

  - pinctrl: sh-pfc: r8a7740: Add missing LCD0 marks to
    lcd0_data24_1 group (bsc#1051510).

  - pinctrl: sh-pfc: r8a7740: Add missing REF125CK pin to
    gether_gmii group (bsc#1051510).

  - pinctrl: sh-pfc: r8a7778: Fix HSPI pin numbers and names
    (bsc#1051510).

  - pinctrl: sh-pfc: r8a7791: Fix scifb2_data_c pin group
    (bsc#1051510).

  - pinctrl: sh-pfc: r8a7791: Remove bogus ctrl marks from
    qspi_data4_b group (bsc#1051510).

  - pinctrl: sh-pfc: r8a7791: Remove bogus marks from
    vin1_b_data18 group (bsc#1051510).

  - pinctrl: sh-pfc: r8a7792: Fix vin1_data18_b pin group
    (bsc#1051510).

  - pinctrl: sh-pfc: r8a7794: Remove bogus IPSR9 field
    (bsc#1051510).

  - pinctrl: sh-pfc: sh7264: Fix PFCR3 and PFCR0 register
    configuration (bsc#1051510).

  - pinctrl: sh-pfc: sh7269: Add missing PCIOR0 field
    (bsc#1051510).

  - pinctrl: sh-pfc: sh73a0: Add missing TO pin to tpu4_to3
    group (bsc#1051510).

  - pinctrl: sh-pfc: sh73a0: Fix fsic_spdif pin groups
    (bsc#1051510).

  - pinctrl: sh-pfc: sh7734: Add missing IPSR11 field
    (bsc#1051510).

  - pinctrl: sh-pfc: sh7734: Fix shifted values in IPSR10
    (bsc#1051510).

  - pinctrl: sh-pfc: sh7734: Remove bogus IPSR10 value
    (bsc#1051510).

  - pinctrl: sunxi: a64: Rename function csi0 to csi
    (bsc#1051510).

  - pinctrl: sunxi: a64: Rename function ts0 to ts
    (bsc#1051510).

  - pinctrl: sunxi: a83t: Fix IRQ offset typo for PH11
    (bsc#1051510).

  - pinctrl: sx150x: handle failure case of devm_kstrdup
    (bsc#1051510).

  - pktcdvd: Fix possible Spectre-v1 for pkt_devs
    (bsc#1051510).

  - platform/x86: Fix unmet dependency warning for
    SAMSUNG_Q10 (bsc#1051510).

  - pm / wakeup: Rework wakeup source timer cancellation
    (bsc#1051510).

  - powercap: intel_rapl: add support for Jacobsville ().

  - powerpc/64s: Clear on-stack exception marker upon
    exception return (bsc#1071995).

  - powerpc/livepatch: relax reliable stack tracer checks
    for first-frame (bsc#1071995).

  - powerpc/livepatch: small cleanups in
    save_stack_trace_tsk_reliable() (bsc#1071995).

  - powerpc/pseries: export timebase register sample in
    lparcfg (bsc#1127750).

  - powerpc/pseries/mce: Fix misleading print for TLB
    mutlihit (bsc#1094244, git-fixes).

  - powerpc/pseries: Perform full re-add of CPU for topology
    update post-migration (bsc#1125728).

  - power: supply: charger-manager: Fix incorrect return
    value (bsc#1051510).

  - pptp: dst_release sk_dst_cache in pptp_sock_destruct
    (git-fixes).

  - proc/sysctl: do not return ENOMEM on lookup when a table
    is unregistering (git-fixes).

  - pseries/energy: Use OF accessor function to read
    ibm,drc-indexes (bsc#1129080).

  - ptp: check gettime64 return code in PTP_SYS_OFFSET ioctl
    (bsc#1051510).

  - ptp: Fix pass zero to ERR_PTR() in ptp_clock_register
    (bsc#1051510).

  - pwm-backlight: Enable/disable the PWM before/after LCD
    enable toggle (bsc#1051510).

  - qmi_wwan: add MTU default to qmap network interface
    (networking-stable-19_01_22).

  - qmi_wwan: apply SET_DTR quirk to Sierra WP7607
    (bsc#1051510).

  - qmi_wwan: Fix qmap header retrieval in qmimux_rx_fixup
    (bsc#1051510).

  - r8169: Add support for new Realtek Ethernet
    (networking-stable-19_01_22).

  - r8169: use PCI_VDEVICE macro
    (networking-stable-19_01_22).

  - rbd: do not return 0 on unmap if RBD_DEV_FLAG_REMOVING
    is set (bsc#1125797).

  - rcu: Fix up pending cbs check in rcu_prepare_for_idle
    (git fixes (kernel/rcu)).

  - rcu: Make need_resched() respond to urgent RCU-QS needs
    (git fixes (kernel/rcu)).

  - rdma/vmw_pvrdma: Support upto 64-bit PFNs (bsc#1127285).

  - Refresh
    patches.suse/scsi-do-not-print-reservation-conflict-for-
    TEST-UNIT.patch (bsc#1119843)

  - regulator: act8865: Fix act8600_sudcdc_voltage_ranges
    setting (bsc#1051510).

  - regulator: max77620: Initialize values for DT properties
    (bsc#1051510).

  - regulator: pv88060: Fix array out-of-bounds access
    (bsc#1051510).

  - regulator: pv88080: Fix array out-of-bounds access
    (bsc#1051510).

  - regulator: pv88090: Fix array out-of-bounds access
    (bsc#1051510).

  - regulator: s2mpa01: Fix step values for some LDOs
    (bsc#1051510).

  - regulator: s2mps11: Fix steps for buck7, buck8 and LDO35
    (bsc#1051510).

  - regulator: wm831x-dcdc: Fix list of wm831x_dcdc_ilim
    from mA to uA (bsc#1051510).

  - Remove blacklist of virtio patch so we can install it
    (bsc#1114585)

  - Remove patches rejected upstream ().

  - Revert drm/i915 patches that caused regressions
    (bsc#1131062)

  - Revert 'drm/rockchip: Allow driver to be shutdown on
    reboot/kexec' (bsc#1051510).

  - Revert 'Input: elan_i2c - add ACPI ID for touchpad in
    ASUS Aspire F5-573G' (bsc#1051510).

  - Revert 'ipv4: keep skb->dst around in presence of IP
    options' (git-fixes).

  - Revert 'openvswitch: Fix template leak in error cases.'
    (bsc#1051510).

  - Revert 'scsi: qla2xxx: Fix NVMe Target discovery'
    (bsc#1125252).

  - Revert 'sd: disable logical block provisioning if
    'lbpme' is not set' This reverts commit
    e365f138cb9c9c48b710864a9f37a91b4b93381d. Patch not
    accepted upstream.

  - Revert the previous merge of drm fixes The branch was
    merged mistakenly and breaks the build. Revert it.

  - Revert 'xhci: Reset Renesas uPD72020x USB controller for
    32-bit DMA issue' (bsc#1120854).

  - rhashtable: Still do rehash when we get EEXIST
    (bsc#1051510).

  - rocker: fix rocker_tlv_put_* functions for KASAN
    (bsc#1051510).

  - rpm/kernel-source.changes.old: Really drop old
    changelogs (bsc#1098995)

  - rt2800: enable TX_PIN_CFG_RFRX_EN only for MT7620
    (bsc#1120902).

  - rtc: 88pm80x: fix unintended sign extension
    (bsc#1051510).

  - rtc: 88pm860x: fix unintended sign extension
    (bsc#1051510).

  - rtc: cmos: ignore bogus century byte (bsc#1051510).

  - rtc: ds1672: fix unintended sign extension
    (bsc#1051510).

  - rtc: Fix overflow when converting time64_t to rtc_time
    (bsc#1051510).

  - rtc: pm8xxx: fix unintended sign extension
    (bsc#1051510).

  - rtnetlink: bring NETDEV_CHANGE_TX_QUEUE_LEN event
    process back in rtnetlink_event (git-fixes).

  - rtnetlink: bring NETDEV_CHANGEUPPER event process back
    in rtnetlink_event (git-fixes).

  - rtnetlink: bring NETDEV_POST_TYPE_CHANGE event process
    back in rtnetlink_event (git-fixes).

  - rtnetlink: check DO_SETLINK_NOTIFY correctly in
    do_setlink (git-fixes).

  - rxrpc: bad unlock balance in rxrpc_recvmsg
    (networking-stable-19_02_10).

  - s390/cio: Fix how vfio-ccw checks pinned pages
    (git-fixes).

  - s390/cpum_cf: Reject request for sampling in event
    initialization (git-fixes).

  - s390/early: improve machine detection (git-fixes).

  - s390/mm: always force a load of the primary ASCE on
    context switch (git-fixes).

  - s390/mm: fix addressing exception after suspend/resume
    (bsc#1125252).

  - s390/qeth: cancel close_dev work before removing a card
    (LTC#175898, bsc#1127561).

  - s390/qeth: conclude all event processing before
    offlining a card (LTC#175901, bsc#1127567).

  - s390/qeth: fix use-after-free in error path
    (bsc#1127534).

  - s390/qeth: invoke softirqs after napi_schedule()
    (git-fixes).

  - s390/smp: Fix calling smp_call_ipl_cpu() from ipl CPU
    (git-fixes).

  - s390/smp: fix CPU hotplug deadlock with CPU rescan
    (git-fixes).

  - s390/sthyi: Fix machine name validity indication
    (git-fixes).

  - sata_rcar: fix deferred probing (bsc#1051510).

  - sc16is7xx: Fix for multi-channel stall (bsc#1051510).

  - sched: Do not re-read h_load_next during hierarchical
    load calculation (bnc#1120909).

  - sched/wake_q: Document wake_q_add() (bsc#1050549).

  - sched/wake_q: Fix wakeup ordering for wake_q
    (bsc#1050549).

  - sched/wake_q: Reduce reference counting for special
    users (bsc#1050549).

  - sch_multiq: fix double free on init failure
    (bsc#1051510).

  - scripts/git_sort/git_sort.py: add vfs 'fixes' branch

  - scsi: core: reset host byte in DID_NEXUS_FAILURE case
    (bsc#1122764).

  - scsi: csiostor: remove flush_scheduled_work()
    (bsc#1127363).

  - scsi: fix queue cleanup race before queue initialization
    is done (bsc#1125252).

  - scsi: ibmvscsi: Fix empty event pool access during host
    removal (bsc#1119019).

  - scsi: ibmvscsi: Protect ibmvscsi_head from concurrent
    modificaiton (bsc#1119019).

  - scsi: libiscsi: fix possible NULL pointer dereference in
    case of TMF (bsc#1127378).

  - scsi: libiscsi: Fix race between iscsi_xmit_task and
    iscsi_complete_task (bsc#1122192).

  - scsi: lpfc: Add log messages to aid in debugging fc4type
    discovery issues (bsc#1121317).

  - scsi: lpfc: Correct MDS loopback diagnostics support
    (bsc#1121317).

  - scsi: lpfc: do not set queue->page_count to 0 if
    pc_sli4_params.wqpcnt is invalid (bsc#1121317).

  - scsi: lpfc: Fix discovery failure when PLOGI is defered
    (bsc#1121317).

  - scsi: lpfc: Fix link state reporting for trunking when
    adapter is offline (bsc#1121317).

  - scsi: lpfc: fix remoteport access (bsc#1125252).

  - scsi: lpfc: remove an unnecessary NULL check
    (bsc#1121317).

  - scsi: lpfc: update fault value on successful trunk
    events (bsc#1121317).

  - scsi: lpfc: Update lpfc version to 12.0.0.10
    (bsc#1121317).

  - scsi: mpt3sas: Add ioc_<level> logging macros
    (bsc#1117108).

  - scsi: mpt3sas: Annotate switch/case fall-through
    (bsc#1117108).

  - scsi: mpt3sas: Convert logging uses with MPT3SAS_FMT and
    reply_q_name to %s: (bsc#1117108).

  - scsi: mpt3sas: Convert logging uses with MPT3SAS_FMT
    without logging levels (bsc#1117108).

  - scsi: mpt3sas: Convert mlsleading uses of pr_<level>
    with MPT3SAS_FMT (bsc#1117108).

  - scsi: mpt3sas: Convert uses of pr_<level> with
    MPT3SAS_FMT to ioc_<level> (bsc#1117108).

  - scsi: mpt3sas: Fix a race condition in
    mpt3sas_base_hard_reset_handler() (bsc#1117108).

  - scsi: mpt3sas: Fix indentation (bsc#1117108).

  - scsi: mpt3sas: Improve kernel-doc headers (bsc#1117108).

  - scsi: mpt3sas: Introduce struct mpt3sas_nvme_cmd
    (bsc#1117108).

  - scsi: mpt3sas: Remove KERN_WARNING from panic uses
    (bsc#1117108).

  - scsi: mpt3sas: Remove set-but-not-used variables
    (bsc#1117108).

  - scsi: mpt3sas: Remove unnecessary parentheses and
    simplify null checks (bsc#1117108).

  - scsi: mpt3sas: Remove unused macro MPT3SAS_FMT
    (bsc#1117108).

  - scsi: mpt3sas: Split _base_reset_handler(),
    mpt3sas_scsih_reset_handler() and
    mpt3sas_ctl_reset_handler() (bsc#1117108).

  - scsi: mpt3sas: Swap I/O memory read value back to cpu
    endianness (bsc#1117108).

  - scsi: mpt3sas: switch to generic DMA API (bsc#1117108).

  - scsi: mpt3sas: Use dma_pool_zalloc (bsc#1117108).

  - scsi: mptsas: Fixup device hotplug for VMware ESXi
    (bsc#1129046).

  - scsi: qla2xxx: Enable FC-NVME on NPIV ports
    (bsc#1094555).

  - scsi: qla2xxx: Fix a typo in MODULE_PARM_DESC
    (bsc#1094555).

  - scsi: qla2xxx: Fix for FC-NVMe discovery for NPIV port
    (bsc#1094555).

  - scsi: qla2xxx: Fix NPIV handling for FC-NVMe
    (bsc#1094555).

  - scsi: qla2xxx: Initialize port speed to avoid setting
    lower speed (bsc#1094555).

  - scsi: qla2xxx: Modify fall-through annotations
    (bsc#1094555).

  - scsi: qla2xxx: Remove unnecessary self assignment
    (bsc#1094555).

  - scsi: qla2xxx: Simplify conditional check (bsc#1094555).

  - scsi: qla2xxx: Update driver version to 10.00.00.12-k
    (bsc#1094555).

  - scsi: storvsc: Fix a race in sub-channel creation that
    can cause panic ().

  - scsi: sym53c8xx: fix NULL pointer dereference panic in
    sym_int_sir() (bsc#1125315).

  - scsi: virtio_scsi: fix pi_bytes{out,in} on 4 KiB block
    size devices (bsc#1114585).

  - sctp: add a ceiling to optlen in some sockopts
    (bnc#1129163).

  - sctp: improve the events for sctp stream adding
    (networking-stable-19_02_01).

  - sctp: improve the events for sctp stream reset
    (networking-stable-19_02_01).

  - sd: disable logical block provisioning if 'lbpme' is not
    set (bsc#1086095 bsc#1078355).

  - selftests/livepatch: add DYNAMIC_DEBUG config dependency
    (bsc#1071995).

  - selftests/livepatch: introduce tests (bsc#1071995).

  - selinux: always allow mounting submounts (bsc#1051510).

  - seq_buf: Make seq_buf_puts() null-terminate the buffer
    (bsc#1051510).

  - serial: 8250_of: assume reg-shift of 2 for mrvl,mmp-uart
    (bsc#1051510).

  - serial: 8250_pci: Fix number of ports for ACCES serial
    cards (bsc#1051510).

  - serial: 8250_pci: Have ACCES cards that use the four
    port Pericom PI7C9X7954 chip use the pci_pericom_setup()
    (bsc#1051510).

  - serial: fix race between flush_to_ldisc and tty_open
    (bsc#1051510).

  - serial: fsl_lpuart: clear parity enable bit when disable
    parity (bsc#1051510).

  - serial: fsl_lpuart: fix maximum acceptable baud rate
    with over-sampling (bsc#1051510).

  - serial: imx: Update cached mctrl value when changing RTS
    (bsc#1051510).

  - serial: uartps: Fix stuck ISR if RX disabled with
    non-empty FIFO (bsc#1051510).

  - skge: potential memory corruption in skge_get_regs()
    (bsc#1051510).

  - sky2: Disable MSI on Dell Inspiron 1545 and Gateway P-79
    (bsc#1051510).

  - sky2: Increase D3 delay again (bsc#1051510).

  - smb311: Improve checking of negotiate security contexts
    (bsc#1051510).

  - smb3: Enable encryption for SMB3.1.1 (bsc#1051510).

  - smb3: Fix 3.11 encryption to Windows and handle
    encrypted smb3 tcon (bsc#1051510).

  - smb3: Fix SMB3.1.1 guest mounts to Samba (bsc#1051510).

  - smb3: remove noisy warning message on mount
    (bsc#1129664).

  - soc: bcm: brcmstb: Do not leak device tree node
    reference (bsc#1051510).

  - soc: fsl: qbman: avoid race in clearing QMan interrupt
    (bsc#1051510).

  - soc/tegra: Do not leak device tree node reference
    (bsc#1051510).

  - spi: pxa2xx: Setup maximum supported DMA transfer length
    (bsc#1051510).

  - spi: ti-qspi: Fix mmap read when more than one CS in use
    (bsc#1051510).

  - spi/topcliff_pch: Fix potential NULL dereference on
    allocation error (bsc#1051510).

  - splice: do not merge into linked buffers (git-fixes).

  - staging: comedi: ni_660x: fix missing break in switch
    statement (bsc#1051510).

  - staging:iio:ad2s90: Make probe handle spi_setup failure
    (bsc#1051510).

  - staging: iio: ad7780: update voltage on read
    (bsc#1051510).

  - staging: iio: adc: ad7280a: handle error from
    __ad7280_read32() (bsc#1051510).

  - staging: iio: adt7316: allow adt751x to use internal
    vref for all dacs (bsc#1051510).

  - staging: iio: adt7316: fix register and bit definitions
    (bsc#1051510).

  - staging: iio: adt7316: fix the dac read calculation
    (bsc#1051510).

  - staging: iio: adt7316: fix the dac write calculation
    (bsc#1051510).

  - staging: rtl8723bs: Fix build error with Clang when
    inlining is disabled (bsc#1051510).

  - staging: speakup: Replace strncpy with memcpy
    (bsc#1051510).

  - staging: wilc1000: fix to set correct value for
    'vif_num' (bsc#1051510).

  - supported.conf

  - svm: Add mutex_lock to protect apic_access_page_done on
    AMD systems (bsc#1129285).

  - svm: Fix improper check when deactivate AVIC
    (bsc#1130335).

  - swiotlb: Add is_swiotlb_active() function (bsc#1120008).

  - swiotlb: Introduce swiotlb_max_mapping_size()
    (bsc#1120008).

  - switchtec: Fix SWITCHTEC_IOCTL_EVENT_IDX_ALL flags
    overwrite (bsc#1051510).

  - switchtec: Remove immediate status check after
    submitting MRPC command (bsc#1051510).

  - sysfs: Disable lockdep for driver bind/unbind files
    (bsc#1051510).

  - tcp: batch tcp_net_metrics_exit (bsc#1122982).

  - tcp: change txhash on SYN-data timeout
    (networking-stable-19_01_20).

  - tcp: handle inet_csk_reqsk_queue_add() failures
    (git-fixes).

  - team: avoid complex list operations in
    team_nl_cmd_options_set() (bsc#1051510).

  - team: Free BPF filter when unregistering netdev
    (bsc#1051510).

  - thermal: bcm2835: Fix crash in bcm2835_thermal_debugfs
    (bsc#1051510).

  - thermal: do not clear passive state during system sleep
    (bsc#1051510).

  - thermal/drivers/hisi: Encapsulate register writes into
    helpers (bsc#1051510).

  - thermal/drivers/hisi: Fix configuration register setting
    (bsc#1051510).

  - thermal: generic-adc: Fix adc to temp interpolation
    (bsc#1051510).

  - thermal: hwmon: inline helpers when CONFIG_THERMAL_HWMON
    is not set (bsc#1051510).

  - thermal/intel_powerclamp: fix truncated kthread name ().

  - thermal: mediatek: fix register index error
    (bsc#1051510).

  - timekeeping: Use proper seqcount initializer
    (bsc#1051510).

  - tipc: eliminate KMSAN uninit-value in strcmp complaint
    (bsc#1051510).

  - tipc: error path leak fixes in tipc_enable_bearer()
    (bsc#1051510).

  - tipc: fix a race condition of releasing subscriber
    object (bsc#1051510).

  - tipc: fix bug in function tipc_nl_node_dump_monitor
    (bsc#1051510).

  - tipc: fix infinite loop when dumping link monitor
    summary (bsc#1051510).

  - tipc: fix RDM/DGRAM connect() regression (bsc#1051510).

  - tipc: fix uninit-value in tipc_nl_compat_bearer_enable
    (bsc#1051510).

  - tipc: fix uninit-value in tipc_nl_compat_doit
    (bsc#1051510).

  - tipc: fix uninit-value in
    tipc_nl_compat_link_reset_stats (bsc#1051510).

  - tipc: fix uninit-value in tipc_nl_compat_link_set
    (bsc#1051510).

  - tipc: fix uninit-value in tipc_nl_compat_name_table_dump
    (bsc#1051510).

  - tpm: fix kdoc for tpm2_flush_context_cmd()
    (bsc#1051510).

  - tpm: Fix some name collisions with drivers/char/tpm.h
    (bsc#1051510).

  - tpm: return a TPM_RC_COMMAND_CODE response if command is
    not implemented (bsc#1051510).

  - tpm: Return the actual size when receiving an
    unsupported command (bsc#1051510).

  - tpm: suppress transmit cmd error logs when TPM 1.2 is
    disabled/deactivated (bsc#1051510).

  - tpm_tis_spi: Pass the SPI IRQ down to the driver
    (bsc#1051510).

  - tpm/tpm_crb: Avoid unaligned reads in crb_recv()
    (bsc#1051510).

  - tpm/tpm_i2c_infineon: switch to i2c_lock_bus(...,
    I2C_LOCK_SEGMENT) (bsc#1051510).

  - tpm: tpm_i2c_nuvoton: use correct command duration for
    TPM 2.x (bsc#1051510).

  - tpm: tpm_try_transmit() refactor error flow
    (bsc#1051510).

  - tracing: Do not free iter->trace in fail path of
    tracing_open_pipe() (bsc#1129581).

  - tracing/uprobes: Fix output for multiple string
    arguments (bsc#1126495).

  - tracing: Use strncpy instead of memcpy for string keys
    in hist triggers (bsc#1129625).

  - Tree connect for SMB3.1.1 must be signed for
    non-encrypted shares (bsc#1051510).

  - tty: ipwireless: Fix potential NULL pointer dereference
    (bsc#1051510).

  - tty: serial: samsung: Properly set flags in autoCTS mode
    (bsc#1051510).

  - ucc_geth: Reset BQL queue when stopping device
    (networking-stable-19_02_01).

  - ucma: fix a use-after-free in ucma_resolve_ip()
    (bsc#1051510).

  - uevent: add alloc_uevent_skb() helper (bsc#1122982).

  - uio: Reduce return paths from uio_write() (bsc#1051510).

  - Update config files. Remove conditional support for SMB2
    and SMB3 :

  - Update
    patches.arch/s390-sles15-zcrypt-fix-specification-except
    ion.patch (LTC#174936, bsc#1123060, bsc#1123061).

  - Update
    patches.fixes/acpi-nfit-Block-function-zero-DSMs.patch
    (bsc#1051510, bsc#1121789).

  - Update
    patches.fixes/acpi-nfit-Fix-command-supported-detection.
    patch (bsc#1051510, bsc#1121789). Add more detailed
    bugzilla reference.

  - uprobes: Fix handle_swbp() vs. unregister() + register()
    race once more (bsc#1051510).

  - usb: Add new USB LPM helpers (bsc#1120902).

  - usb: cdc-acm: fix race during wakeup blocking TX traffic
    (bsc#1129770).

  - usb: common: Consider only available nodes for dr_mode
    (bsc#1129770).

  - usb: Consolidate LPM checks to avoid enabling LPM twice
    (bsc#1120902).

  - usb: core: only clean up what we allocated
    (bsc#1051510).

  - usb: dwc3: Correct the logic for checking TRB full in
    __dwc3_prepare_one_trb() (bsc#1051510).

  - usb: dwc3: gadget: Disable CSP for stream OUT ep
    (bsc#1051510).

  - usb: dwc3: gadget: Fix the uninitialized link_state when
    udc starts (bsc#1051510).

  - usb: dwc3: gadget: Handle 0 xfer length for OUT EP
    (bsc#1051510).

  - usb: dwc3: gadget: synchronize_irq dwc irq in suspend
    (bsc#1051510).

  - usb: gadget: f_hid: fix deadlock in f_hidg_write()
    (bsc#1129770).

  - usb: gadget: musb: fix short isoc packets with inventra
    dma (bsc#1051510).

  - usb: gadget: Potential NULL dereference on allocation
    error (bsc#1051510).

  - usb: gadget: udc: net2272: Fix bitwise and boolean
    operations (bsc#1051510).

  - usb: hub: delay hub autosuspend if USB3 port is still
    link training (bsc#1051510).

  - usb: mtu3: fix the issue about SetFeature(U1/U2_Enable)
    (bsc#1051510).

  - usb: musb: dsps: fix otg state machine (bsc#1051510).

  - usb: musb: dsps: fix runtime pm for peripheral mode
    (bsc#1120902).

  - usbnet: smsc95xx: fix rx packet alignment (bsc#1051510).

  - usb: phy: am335x: fix race condition in _probe
    (bsc#1051510).

  - usb: phy: fix link errors (bsc#1051510).

  - usb: phy: twl6030-usb: fix possible use-after-free on
    remove (bsc#1051510).

  - usb: serial: cp210x: add ID for Ingenico 3070
    (bsc#1129770).

  - usb: serial: ftdi_sio: add ID for Hjelmslund Electronics
    USB485 (bsc#1129770).

  - usb: serial: mos7720: fix mos_parport refcount imbalance
    on error path (bsc#1129770).

  - usb: serial: option: add Telit ME910 ECM composition
    (bsc#1129770).

  - usb: serial: option: set driver_info for SIM5218 and
    compatibles (bsc#1129770).

  - usb: serial: pl2303: add new PID to support PL2303TB
    (bsc#1051510).

  - usb: serial: simple: add Motorola Tetra TPG2200 device
    id (bsc#1051510).

  - veth: set peer GSO values (bsc#1051510).

  - vfio: ccw: fix cleanup if cp_prefetch fails (git-fixes).

  - vfio: ccw: process ssch with interrupts disabled
    (git-fixes).

  - vfs: Add iomap_seek_hole and iomap_seek_data helpers
    (bsc#1070995).

  - vfs: Add page_cache_seek_hole_data helper (bsc#1070995).

  - vfs: in iomap seek_{hole,data}, return -ENXIO for
    negative offsets (bsc#1070995).

  - vhost: correctly check the return value of
    translate_desc() in log_used() (bsc#1051510).

  - vhost: log dirty page correctly
    (networking-stable-19_01_26).

  - vhost/vsock: fix uninitialized vhost_vsock->guest_cid
    (bsc#1051510).

  - video: clps711x-fb: release disp device node in probe()
    (bsc#1051510).

  - virtio-blk: Consider virtio_max_dma_size() for maximum
    segment size (bsc#1120008).

  - virtio: Introduce virtio_max_dma_size() (bsc#1120008).

  - virtio_net: Do not call free_old_xmit_skbs for
    xdp_frames (networking-stable-19_02_01).

  - virtio/s390: avoid race on vcdev->config (git-fixes).

  - virtio/s390: fix race in ccw_io_helper() (git-fixes).

  - vmci: Support upto 64-bit PPNs (bsc#1127286).

  - vsock: cope with memory allocation failure at socket
    creation time (bsc#1051510).

  - vxge: ensure data0 is initialized in when fetching
    firmware version information (bsc#1051510).

  - vxlan: Fix GRO cells race condition between receive and
    link delete (git-fixes).

  - vxlan: test dev->flags & IFF_UP before calling
    gro_cells_receive() (git-fixes).

  - vxlan: update skb dst pmtu on tx path (bsc#1123456).

  - w90p910_ether: remove incorrect __init annotation
    (bsc#1051510).

  - watchdog: docs: kernel-api: do not reference removed
    functions (bsc#1051510).

  - x86: Add TSX Force Abort CPUID/MSR (bsc#1121805).

  - x86/a.out: Clear the dump structure initially
    (bsc#1114279).

  - x86/apic: Provide apic_ack_irq() (bsc#1122822).

  - x86/boot/e820: Avoid overwriting e820_table_firmware
    (bsc#1127154).

  - x86/boot/e820: Introduce the bootloader provided
    e820_table_firmware[] table (bsc#1127154).

  - x86/boot/e820: Rename the e820_table_firmware to
    e820_table_kexec (bsc#1127154).

  - x86/cpu: Add Atom Tremont (Jacobsville) ().

  - x86/CPU/AMD: Set the CPB bit unconditionally on F17h
    (bsc#1114279).

  - x86/efi: Allocate e820 buffer before calling
    efi_exit_boot_service (bsc#1127307).

  - x86/Hyper-V: Set x2apic destination mode to physical
    when x2apic is available (bsc#1122822).

  - x86/kaslr: Fix incorrect i8254 outb() parameters
    (bsc#1114279).

  - x86/mce: Improve error message when kernel cannot
    recover, p2 (bsc#1114279).

  - x86/mtrr: Do not copy uninitialized gentry fields back
    to userspace (bsc#1114279).

  - x86/pkeys: Properly copy pkey state at fork()
    (bsc#1129366).

  - x86/platform/UV: Use efi_runtime_lock to serialise BIOS
    calls (bsc#1125614).

  - x86: respect memory size limiting via mem= parameter
    (bsc#1117645).

  - x86/vdso: Remove obsolete 'fake section table'
    reservation (bsc#1114279).

  - x86/xen: dont add memory above max allowed allocation
    (bsc#1117645).

  - xen, cpu_hotplug: Prevent an out of bounds access
    (bsc#1065600).

  - xen: fix dom0 boot on huge systems (bsc#1127836).

  - xen/manage: do not complain about an empty value in
    control/sysrq node (bsc#1065600).

  - xen: remove pre-xen3 fallback handlers (bsc#1065600).

  - xfs: add option to mount with barrier=0 or barrier=1
    (bsc#1088133).

  - xfs: fix contiguous dquot chunk iteration livelock
    (bsc#1070995).

  - xfs: remove filestream item xfs_inode reference
    (bsc#1127961).

  - xfs: rewrite xfs_dq_get_next_id using
    xfs_iext_lookup_extent (bsc#1070995).

  - xfs: Switch to iomap for SEEK_HOLE / SEEK_DATA
    (bsc#1070995).

  - yama: Check for pid death before checking ancestry
    (bsc#1051510).

  - yam: fix a missing-check bug (bsc#1051510).

  - zswap: re-check zswap_is_full() after do zswap_shrink()
    (bsc#1051510).

  - x86/uaccess: Do not leak the AC flag into __put_user()
    value evaluation (bsc#1114279)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046306"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060463"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114585"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120601"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=824948"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/15");
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

if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-debuginfo-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debuginfo-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debugsource-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-debuginfo-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-debuginfo-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debuginfo-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debugsource-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-debuginfo-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-devel-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-docs-html-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debugsource-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-macros-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-debugsource-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-qa-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-vanilla-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-syms-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debuginfo-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debugsource-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-4.12.14-lp150.12.58.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp150.12.58.1") ) flag++;

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
