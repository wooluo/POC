#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1570.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126033);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/20 11:24:24");

  script_cve_id("CVE-2013-4343", "CVE-2018-7191", "CVE-2019-11190", "CVE-2019-11191", "CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479", "CVE-2019-11487", "CVE-2019-11833", "CVE-2019-12380", "CVE-2019-12382", "CVE-2019-12456", "CVE-2019-12818", "CVE-2019-12819", "CVE-2019-3846", "CVE-2019-5489");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-1570) (SACK Panic) (SACK Slowness)");
  script_summary(english:"Check for the openSUSE-2019-1570 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Example: The openSUSE Leap 42.3 kernel was updated to 4.4.180 to
receive various security and bugfixes.

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

  - CVE-2019-12456: An issue was discovered in the
    MPT3COMMAND case in _ctl_ioctl_main in
    drivers/scsi/mpt3sas/mpt3sas_ctl.c that allowed local
    users to cause a denial of service or possibly have
    unspecified other impact by changing the value of
    ioc_number between two kernel reads of that value, aka a
    'double fetch' vulnerability (bnc#1136922).

  - CVE-2019-12380: phys_efi_set_virtual_address_map in
    arch/x86/platform/efi/efi.c and efi_call_phys_prolog in
    arch/x86/platform/efi/efi_64.c mishandle memory
    allocation failures (bnc#1136598).

  - CVE-2019-11487: The Linux kernel allowed page->_refcount
    reference count overflow, with resultant use-after-free
    issues, if about 140 GiB of RAM exists. This is related
    to fs/fuse/dev.c, fs/pipe.c, fs/splice.c,
    include/linux/mm.h, include/linux/pipe_fs_i.h,
    kernel/trace/trace.c, mm/gup.c, and mm/hugetlb.c. It can
    occur with FUSE requests (bnc#1133190).

  - CVE-2019-3846: A flaw that allowed an attacker to
    corrupt memory and possibly escalate privileges was
    found in the mwifiex kernel module while connecting to a
    malicious wireless network (bnc#1136424).

  - CVE-2019-12382: An issue was discovered in
    drm_load_edid_firmware in
    drivers/gpu/drm/drm_edid_load.c. There was an unchecked
    kstrdup of fwstr, which might allow an attacker to cause
    a denial of service (NULL pointer dereference and system
    crash) (bnc#1136586).

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

  - CVE-2019-11190, CVE-2019-11191: The Linux kernel allowed
    local users to bypass ASLR on setuid programs (such as
    /bin/su) because install_exec_creds() is called too late
    in load_elf_binary() in fs/binfmt_elf.c, and thus the
    ptrace_may_access() check has a race condition when
    reading /proc/pid/stat (bnc#1131543 bnc#1132374
    bnc#1132472).

The following non-security bugs were fixed :

  - ALSA: line6: use dynamic buffers (bnc#1012382).

  - ARM: dts: pfla02: increase phy reset duration
    (bnc#1012382).

  - ARM: iop: do not use using 64-bit DMA masks
    (bnc#1012382).

  - ARM: orion: do not use using 64-bit DMA masks
    (bnc#1012382).

  - ASoC: cs4270: Set auto-increment bit for register writes
    (bnc#1012382).

  - ASoC: Intel: avoid Oops if DMA setup fails
    (bnc#1012382).

  - ASoC:soc-pcm:fix a codec fixup issue in TDM case
    (bnc#1012382).

  - ASoC: tlv320aic32x4: Fix Common Pins (bnc#1012382).

  - ath6kl: Only use match sets when firmware supports it
    (bsc#1120902).

  - backlight: lm3630a: Return 0 on success in update_status
    functions (bsc#1106929)

  - bitops: avoid integer overflow in GENMASK(_ULL)
    (bnc#1012382).

  - block: fix use-after-free on gendisk (bsc#1136448).

  - bluetooth: Align minimum encryption key size for LE and
    BR/EDR connections (bnc#1012382).

  - bnxt_en: Improve multicast address setup logic
    (bnc#1012382).

  - bonding: fix arp_validate toggling in active-backup mode
    (bnc#1012382).

  - bonding: show full hw address in sysfs for slave entries
    (bnc#1012382).

  - bpf: reject wrong sized filters earlier (bnc#1012382).

  - bridge: Fix error path for kobject_init_and_add()
    (bnc#1012382).

  - btrfs: add a helper to return a head ref (bsc#1134813).

  - btrfs: breakout empty head cleanup to a helper
    (bsc#1134813).

  - btrfs: delayed-ref: Introduce better documented delayed
    ref structures (bsc#1063638 bsc#1128052 bsc#1108838).

  - btrfs: delayed-ref: Use btrfs_ref to refactor
    btrfs_add_delayed_data_ref() (bsc#1063638 bsc#1128052
    bsc#1108838).

  - btrfs: delayed-ref: Use btrfs_ref to refactor
    btrfs_add_delayed_tree_ref() (bsc#1063638 bsc#1128052
    bsc#1108838).

  - btrfs: extent-tree: Fix a bug that btrfs is unable to
    add pinned bytes (bsc#1063638 bsc#1128052 bsc#1108838).

  - btrfs: extent-tree: Open-code process_func in
    __btrfs_mod_ref (bsc#1063638 bsc#1128052 bsc#1108838).

  - btrfs: extent-tree: Use btrfs_ref to refactor
    add_pinned_bytes() (bsc#1063638 bsc#1128052
    bsc#1108838).

  - btrfs: extent-tree: Use btrfs_ref to refactor
    btrfs_free_extent() (bsc#1063638 bsc#1128052
    bsc#1108838).

  - btrfs: extent-tree: Use btrfs_ref to refactor
    btrfs_inc_extent_ref() (bsc#1063638 bsc#1128052
    bsc#1108838).

  - btrfs: Factor out common delayed refs init code
    (bsc#1134813).

  - btrfs: Introduce init_delayed_ref_head (bsc#1134813).

  - btrfs: move all ref head cleanup to the helper function
    (bsc#1134813).

  - btrfs: move extent_op cleanup to a helper (bsc#1134813).

  - btrfs: move ref_mod modification into the if (ref) logic
    (bsc#1134813).

  - btrfs: Open-code add_delayed_data_ref (bsc#1134813).

  - btrfs: Open-code add_delayed_tree_ref (bsc#1134813).

  - btrfs: qgroup: Check bg while resuming relocation to
    avoid NULL pointer dereference (bsc#1134806).

  - btrfs: qgroup: Do not scan leaf if we're modifying reloc
    tree (bsc#1063638 bsc#1128052 bsc#1108838).

  - btrfs: reloc: Also queue orphan reloc tree for cleanup
    to avoid BUG_ON() (bsc#1134338).

  - btrfs: remove delayed_ref_node from ref_head
    (bsc#1134813).

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

  - cdc-acm: cleaning up debug in data submission path
    (bsc#1136539).

  - cdc-acm: fix race between reset and control messaging
    (bsc#1106110).

  - cdc-acm: handle read pipe errors (bsc#1135878).

  - cdc-acm: reassemble fragmented notifications
    (bsc#1136590).

  - cdc-acm: store in and out pipes in acm structure
    (bsc#1136575).

  - cifs: do not attempt cifs operation on smb2+ rename
    error (bnc#1012382).

  - cifs: keep FileInfo handle live during oplock break
    (bsc#1106284, bsc#1131565).

  - clk: fix mux clock documentation (bsc#1090888).

  - cpu/hotplug: Provide cpus_read|write_[un]lock()
    (bsc#1138374, LTC#178199).

  - cpu/hotplug: Provide lockdep_assert_cpus_held()
    (bsc#1138374, LTC#178199).

  - cpupower: remove stringop-truncation waring
    (bsc#1119086).

  - cpu/speculation: Add 'mitigations=' cmdline option
    (bnc#1012382 bsc#1112178).

  - crypto: vmx - CTR: always increment IV as quadword
    (bsc#1135661, bsc#1137162).

  - crypto: vmx - fix copy-paste error in CTR mode
    (bsc#1135661, bsc#1137162).

  - crypto: vmx - ghash: do nosimd fallback manually
    (bsc#1135661, bsc#1137162).

  - crypto: vmx: Only call enable_kernel_vsx() (bsc#1135661,
    bsc#1137162).

  - crypto: vmx - return correct error code on failed setkey
    (bsc#1135661, bsc#1137162).

  - debugfs: fix use-after-free on symlink traversal
    (bnc#1012382).

  - Documentation: Add MDS vulnerability documentation
    (bnc#1012382).

  - Documentation: Add nospectre_v1 parameter (bnc#1012382).

  - Documentation: Correct the possible MDS sysfs values
    (bnc#1012382).

  - Documentation: Move L1TF to separate directory
    (bnc#1012382).

  - Do not jump to compute_result state from check_result
    state (bnc#1012382).

  - drivers/virt/fsl_hypervisor.c: dereferencing error
    pointers in ioctl (bnc#1012382).

  - drivers/virt/fsl_hypervisor.c: prevent integer overflow
    in ioctl (bnc#1012382).

  - drm/bridge: adv7511: Fix low refresh rate selection
    (bsc#1106929)

  - drm/rockchip: shutdown drm subsystem on shutdown
    (bsc#1106929)

  - drm/vmwgfx: integer underflow in vmw_cmd_dx_set_shader()
    leading to (bsc#1106929)

  - drm/vmwgfx: NULL pointer dereference from
    vmw_cmd_dx_view_define() (bsc#1106929)

  - Drop multiversion(kernel) from the KMP template
    (bsc#1127155).

  - dt-bindings: rcar-dmac: Document missing error interrupt
    (bsc#1085535).

  - exportfs: fix 'passing zero to ERR_PTR()' warning
    (bsc#1136458).

  - ext4: actually request zeroing of inode table after grow
    (bsc#1136451).

  - ext4: avoid panic during forced reboot due to aborted
    journal (bsc#1126356).

  - ext4: fix ext4_show_options for file systems w/o journal
    (bsc#1136452).

  - ext4: fix use-after-free race with
    debug_want_extra_isize (bsc#1136449).

  - ext4: make sure enough credits are reserved for
    dioread_nolock writes (bsc#1136623).

  - ext4: Return EAGAIN in case of DIO is beyond end of file
    (bsc#1136810).

  - ext4: wait for outstanding dio during truncate in
    nojournal mode (bsc#1136438).

  - fs/proc/proc_sysctl.c: Fix a NULL pointer dereference
    (bnc#1012382).

  - ftrace/x86_64: Emulate call function while updating in
    breakpoint handler (bsc#1099658).

  - genirq: Prevent use-after-free and work list corruption
    (bnc#1012382).

  - gpu: ipu-v3: dp: fix CSC handling (bnc#1012382).

  - HID: debug: fix race condition with between rdesc_show()
    and device removal (bnc#1012382).

  - HID: input: add mapping for Expose/Overview key
    (bnc#1012382).

  - HID: input: add mapping for keyboard Brightness
    Up/Down/Toggle keys (bnc#1012382).

  - hugetlbfs: fix memory leak for resv_map (bnc#1012382).

  - IB/hfi1: Eliminate opcode tests on mr deref ().

  - IB/hfi1: Unreserve a reserved request when it is
    completed ().

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

  - IB/rdmavt: Add wc_flags and wc_immdata to cq entry trace
    ().

  - IB/rdmavt: Fix frwr memory registration ().

  - igb: Fix WARN_ONCE on runtime suspend (bnc#1012382).

  - iio: adc: xilinx: fix potential use-after-free on remove
    (bnc#1012382).

  - init: initialize jump labels before command line option
    parsing (bnc#1012382).

  - Input: snvs_pwrkey - initialize necessary driver data
    before enabling IRQ (bnc#1012382).

  - ipmi:ssif: compare block number correctly for multi-part
    return messages (bsc#1135120).

  - ipv4: Fix raw socket lookup for local traffic
    (bnc#1012382).

  - ipv4: ip_do_fragment: Preserve skb_iif during
    fragmentation (bnc#1012382).

  - ipv4: set the tcp_min_rtt_wlen range from 0 to one day
    (bnc#1012382).

  - ipv6: fix a potential deadlock in do_ipv6_setsockopt()
    (bnc#1012382).

  - ipv6/flowlabel: wait rcu grace period before put_pid()
    (bnc#1012382).

  - ipv6: invert flowlabel sharing check in process and user
    mode (bnc#1012382).

  - ipvs: do not schedule icmp errors from tunnels
    (bnc#1012382).

  - iwiwifi: fix bad monitor buffer register addresses
    (bsc#1129770).

  - jffs2: fix use-after-free on symlink traversal
    (bnc#1012382).

  - kabi: drop LINUX_MIB_TCPWQUEUETOOBIG snmp counter
    (bsc#1137586).

  - kabi: move sysctl_tcp_min_snd_mss to preserve struct net
    layout (bsc#1137586).

  - kbuild: simplify ld-option implementation (bnc#1012382).

  - kconfig: display recursive dependency resolution hint
    just once (bsc#1100132).

  - kconfig/[mn]conf: handle backspace (^H) key
    (bnc#1012382).

  - keys: Timestamp new keys (bsc#1120902).

  - KVM: fail KVM_SET_VCPU_EVENTS with invalid exception
    number (bnc#1012382).

  - KVM: x86: avoid misreporting level-triggered irqs as
    edge-triggered in tracing (bnc#1012382).

  - libata: fix using DMA buffers on stack (bnc#1012382).

  - libertas_tf: prevent underflow in process_cmdrequest()
    (bsc#1119086).

  - libnvdimm/btt: Fix a kmemdup failure check
    (bnc#1012382).

  - mac80211_hwsim: validate number of different channels
    (bsc#1085539).

  - media: pvrusb2: Prevent a buffer overflow (bsc#1135642).

  - media: v4l2: i2c: ov7670: Fix PLL bypass register values
    (bnc#1012382).

  - MIPS: scall64-o32: Fix indirect syscall number load
    (bnc#1012382).

  - mount: copy the port field into the cloned nfs_server
    structure (bsc#1136990).

  - mwifiex: Fix heap overflow in
    mwifiex_uap_parse_tail_ies() (bsc#1136935).

  - net: ena: fix return value of ena_com_config_llq_info()
    (bsc#1117562).

  - net: ethernet: ti: fix possible object reference leak
    (bnc#1012382).

  - netfilter: bridge: set skb transport_header before
    entering NF_INET_PRE_ROUTING (bnc#1012382).

  - netfilter: compat: initialize all fields in xt_init
    (bnc#1012382).

  - netfilter: ebtables: CONFIG_COMPAT: drop a bogus WARN_ON
    (bnc#1012382).

  - net: hns: Fix WARNING when remove HNS driver with SMMU
    enabled (bnc#1012382).

  - net: hns: Use NAPI_POLL_WEIGHT for hns driver
    (bnc#1012382).

  - net: ibm: fix possible object reference leak
    (bnc#1012382).

  - net/ibmvnic: Remove tests of member address
    (bsc#1137739).

  - net: ks8851: Delay requesting IRQ until opened
    (bnc#1012382).

  - net: ks8851: Dequeue RX packets explicitly
    (bnc#1012382).

  - net: ks8851: Reassert reset pin if chip ID check fails
    (bnc#1012382).

  - net: ks8851: Set initial carrier state to down
    (bnc#1012382).

  - net: Remove NO_IRQ from powerpc-only network drivers
    (bsc#1137739).

  - net: stmmac: move stmmac_check_ether_addr() to driver
    probe (bnc#1012382).

  - net: ucc_geth - fix Oops when changing number of buffers
    in the ring (bnc#1012382).

  - net: xilinx: fix possible object reference leak
    (bnc#1012382).

  - nfsd: Do not release the callback slot unless it was
    actually held (bnc#1012382).

  - NFS: Forbid setting AF_INET6 to 'struct
    sockaddr_in'->sin_family (bnc#1012382).

  - ntp: Allow TAI-UTC offset to be set to zero
    (bsc#1135642).

  - nvme: Do not allow to reset a reconnecting controller
    (bsc#1133874).

  - packet: Fix error path in packet_init (bnc#1012382).

  - packet: validate msg_namelen in send directly
    (bnc#1012382).

  - PCI: Mark AMD Stoney Radeon R7 GPU ATS as broken
    (bsc#1137142).

  - PCI: Mark Atheros AR9462 to avoid bus reset
    (bsc#1135642).

  - perf/x86/intel: Allow PEBS multi-entry in watermark mode
    (git-fixes).

  - perf/x86/intel: Fix handling of wakeup_events for
    multi-entry PEBS (bnc#1012382).

  - platform/x86: sony-laptop: Fix unintentional
    fall-through (bnc#1012382).

  - powerpc/64: Add CONFIG_PPC_BARRIER_NOSPEC (bnc#1012382).

  - powerpc/64: Call setup_barrier_nospec() from
    setup_arch() (bnc#1012382 bsc#1131107).

  - powerpc/64: Make meltdown reporting Book3S 64 specific
    (bnc#1012382).

  - powerpc/64s: Include cpu header (bnc#1012382).

  - powerpc/booke64: set RI in default MSR (bnc#1012382).

  - powerpc/cacheinfo: add cacheinfo_teardown,
    cacheinfo_rebuild (bsc#1138374, LTC#178199).

  - powerpc/eeh: Fix race with driver un/bind (bsc#1066223).

  - powerpc/fsl: Add barrier_nospec implementation for NXP
    PowerPC Book3E (bnc#1012382).

  - powerpc/fsl: Add FSL_PPC_BOOK3E as supported arch for
    nospectre_v2 boot arg (bnc#1012382).

  - powerpc/fsl: Add infrastructure to fixup branch
    predictor flush (bnc#1012382).

  - powerpc/fsl: Add macro to flush the branch predictor
    (bnc#1012382).

  - powerpc/fsl: Add nospectre_v2 command line argument
    (bnc#1012382).

  - powerpc/fsl: Emulate SPRN_BUCSR register (bnc#1012382).

  - powerpc/fsl: Enable runtime patching if nospectre_v2
    boot arg is used (bnc#1012382).

  - powerpc/fsl: Fixed warning: orphan section
    `__btb_flush_fixup' (bnc#1012382).

  - powerpc/fsl: Fix the flush of branch predictor
    (bnc#1012382).

  - powerpc/fsl: Flush branch predictor when entering KVM
    (bnc#1012382).

  - powerpc/fsl: Flush the branch predictor at each kernel
    entry (32 bit) (bnc#1012382).

  - powerpc/fsl: Flush the branch predictor at each kernel
    entry (64bit) (bnc#1012382).

  - powerpc/fsl: Sanitize the syscall table for NXP PowerPC
    32 bit platforms (bnc#1012382).

  - powerpc/fsl: Update Spectre v2 reporting (bnc#1012382).

  - powerpc/lib: fix book3s/32 boot failure due to code
    patching (bnc#1012382).

  - powerpc/perf: Add blacklisted events for Power9 DD2.1
    (bsc#1053043).

  - powerpc/perf: Add blacklisted events for Power9 DD2.2
    (bsc#1053043).

  - powerpc/perf: Fix MMCRA corruption by bhrb_filter
    (bsc#1053043).

  - powerpc/perf: Infrastructure to support addition of
    blacklisted events (bsc#1053043).

  - powerpc/process: Fix sparse address space warnings
    (bsc#1066223).

  - powerpc/pseries/mobility: prevent cpu hotplug during DT
    update (bsc#1138374, LTC#178199).

  - powerpc/pseries/mobility: rebuild cacheinfo hierarchy
    post-migration (bsc#1138374, LTC#178199).

  - powerpc/xmon: Add RFI flush related fields to paca dump
    (bnc#1012382).

  - qede: fix write to free'd pointer error and double free
    of ptp (bsc#1019695 bsc#1019696).

  - qlcnic: Avoid potential NULL pointer dereference
    (bnc#1012382).

  - RDMA/iw_cxgb4: Fix the unchecked ep dereference
    (bsc#1005778 bsc#1005780 bsc#1005781).

  - RDMA/qedr: Fix out of bounds index check in query pkey
    (bsc#1022604).

  - Revert 'block/loop: Use global lock for ioctl()
    operation.' (bnc#1012382).

  - Revert 'cpu/speculation: Add 'mitigations=' cmdline
    option' (stable backports).

  - Revert 'Do not jump to compute_result state from
    check_result state' (git-fixes).

  - Revert 'KMPs: obsolete older KMPs of the same flavour
    (bsc#1127155, bsc#1109137).' This reverts commit
    4cc83da426b53d47f1fde9328112364eab1e9a19.

  - Revert 'sched: Add sched_smt_active()' (stable
    backports).

  - Revert 'x86/MCE: Save microcode revision in machine
    check records' (kabi).

  - Revert 'x86/speculation/mds: Add 'mitigations=' support
    for MDS' (stable backports).

  - Revert 'x86/speculation: Support 'mitigations=' cmdline
    option' (stable backports).

  - rtc: da9063: set uie_unsupported when relevant
    (bnc#1012382).

  - rtc: sh: Fix invalid alarm warning for non-enabled alarm
    (bnc#1012382).

  - rtlwifi: fix false rates in
    _rtl8821ae_mrate_idx_to_arfr_id() (bsc#1120902).

  - s390/3270: fix lockdep false positive on view->lock
    (bnc#1012382).

  - s390: ctcm: fix ctcm_new_device error return code
    (bnc#1012382).

  - s390/dasd: Fix capacity calculation for large volumes
    (bnc#1012382).

  - sc16is7xx: missing unregister/delete driver on error in
    sc16is7xx_init() (bnc#1012382).

  - sc16is7xx: move label 'err_spi' to correct section
    (git-fixes).

  - sched: Add sched_smt_active() (bnc#1012382).

  - sched/numa: Fix a possible divide-by-zero (bnc#1012382).

  - scsi: csiostor: fix missing data copy in
    csio_scsi_err_handler() (bnc#1012382).

  - scsi: libsas: fix a race condition when smp task timeout
    (bnc#1012382).

  - scsi: qla2xxx: Fix incorrect region-size setting in
    optrom SYSFS routines (bnc#1012382).

  - scsi: qla4xxx: fix a potential NULL pointer dereference
    (bnc#1012382).

  - scsi: storvsc: Fix calculation of sub-channel count
    (bnc#1012382).

  - scsi: zfcp: reduce flood of fcrscn1 trace records on
    multi-element RSCN (bnc#1012382).

  - selftests/net: correct the return value for
    run_netsocktests (bnc#1012382).

  - selinux: never allow relabeling on context mounts
    (bnc#1012382).

  - signals: avoid random wakeups in sigsuspend()
    (bsc#1137915)

  - slip: make slhc_free() silently accept an error pointer
    (bnc#1012382).

  - staging: iio: adt7316: allow adt751x to use internal
    vref for all dacs (bnc#1012382).

  - staging: iio: adt7316: fix the dac read calculation
    (bnc#1012382).

  - staging: iio: adt7316: fix the dac write calculation
    (bnc#1012382).

  - tcp: add tcp_min_snd_mss sysctl (bsc#1137586).

  - tcp: enforce tcp_min_snd_mss in tcp_mtu_probing()
    (bsc#1137586).

  - tcp: limit payload size of sacked skbs (bsc#1137586).

  - tcp: tcp_fragment() should apply sane memory limits
    (bsc#1137586).

  - team: fix possible recursive locking when add slaves
    (bnc#1012382).

  - timer/debug: Change /proc/timer_stats from 0644 to 0600
    (bnc#1012382).

  - tipc: check bearer name with right length in
    tipc_nl_compat_bearer_enable (bnc#1012382).

  - tipc: check link name with right length in
    tipc_nl_compat_link_set (bnc#1012382).

  - tipc: handle the err returned from cmd header function
    (bnc#1012382).

  - tools lib traceevent: Fix missing equality check for
    strcmp (bsc#1129770).

  - trace: Fix preempt_enable_no_resched() abuse
    (bnc#1012382).

  - tracing: Fix partial reading of trace event's id file
    (bsc#1136573).

  - treewide: Use DEVICE_ATTR_WO (bsc#1137739).

  - UAS: fix alignment of scatter/gather segments
    (bnc#1012382 bsc#1129770).

  - ufs: fix braino in ufs_get_inode_gid() for solaris UFS
    flavour (bsc#1136455).

  - Update config files: disable IDE on ppc64le

  - usb: cdc-acm: fix race during wakeup blocking TX traffic
    (bsc#1129770).

  - usb: cdc-acm: fix unthrottle races (bsc#1135642).

  - usb: core: Fix bug caused by duplicate interface PM
    usage counter (bnc#1012382).

  - usb: core: Fix unterminated string returned by
    usb_string() (bnc#1012382).

  - usb: dwc3: Fix default lpm_nyet_threshold value
    (bnc#1012382).

  - usb: gadget: net2272: Fix net2272_dequeue()
    (bnc#1012382).

  - usb: gadget: net2280: Fix net2280_dequeue()
    (bnc#1012382).

  - usb: gadget: net2280: Fix overrun of OUT messages
    (bnc#1012382).

  - usbnet: ipheth: fix potential NULL pointer dereference
    in ipheth_carrier_set (bnc#1012382).

  - usbnet: ipheth: prevent TX queue timeouts when device
    not ready (bnc#1012382).

  - usb: serial: fix unthrottle races (bnc#1012382).

  - usb: serial: use variable for status (bnc#1012382).

  - usb: u132-hcd: fix resource leak (bnc#1012382).

  - usb: usbip: fix isoc packet num validation in get_pipe
    (bnc#1012382).

  - usb: w1 ds2490: Fix bug caused by improper use of
    altsetting array (bnc#1012382).

  - usb: yurex: Fix protection fault after device removal
    (bnc#1012382).

  - vfio/pci: use correct format characters (bnc#1012382).

  - vlan: disable SIOCSHWTSTAMP in container (bnc#1012382).

  - vrf: sit mtu should not be updated when vrf netdev is
    the link (bnc#1012382).

  - x86_64: Add gap to int3 to allow for call emulation
    (bsc#1099658).

  - x86_64: Allow breakpoints to emulate call instructions
    (bsc#1099658).

  - x86/bugs: Add AMD's SPEC_CTRL MSR usage (bnc#1012382).

  - x86/bugs: Change L1TF mitigation string to match
    upstream (bnc#1012382).

  - x86/bugs: Fix the AMD SSBD usage of the SPEC_CTRL MSR
    (bnc#1012382).

  - x86/bugs: Switch the selection of mitigation from CPU
    vendor to CPU features (bnc#1012382).

  - x86/cpu/bugs: Use __initconst for 'const' init data
    (bnc#1012382).

  - x86/cpufeatures: Hide AMD-specific speculation flags
    (bnc#1012382).

  - x86/Kconfig: Select SCHED_SMT if SMP enabled
    (bnc#1012382).

  - x86/MCE: Save microcode revision in machine check
    records (bnc#1012382).

  - x86/mds: Add MDSUM variant to the MDS documentation
    (bnc#1012382).

  - x86/microcode/intel: Add a helper which gives the
    microcode revision (bnc#1012382).

  - x86/microcode/intel: Check microcode revision before
    updating sibling threads (bnc#1012382).

  - x86/microcode: Make sure boot_cpu_data.microcode is
    up-to-date (bnc#1012382).

  - x86/microcode: Update the new microcode revision
    unconditionally (bnc#1012382).

  - x86/mm: Use WRITE_ONCE() when setting PTEs
    (bnc#1012382).

  - x86/process: Consolidate and simplify switch_to_xtra()
    code (bnc#1012382).

  - x86/speculataion: Mark command line parser data
    __initdata (bnc#1012382).

  - x86/speculation: Add command line control for indirect
    branch speculation (bnc#1012382).

  - x86/speculation: Add prctl() control for indirect branch
    speculation (bnc#1012382).

  - x86/speculation: Add seccomp Spectre v2 user space
    protection mode (bnc#1012382).

  - x86/speculation: Avoid __switch_to_xtra() calls
    (bnc#1012382).

  - x86/speculation: Clean up spectre_v2_parse_cmdline()
    (bnc#1012382).

  - x86/speculation: Disable STIBP when enhanced IBRS is in
    use (bnc#1012382).

  - x86/speculation: Enable prctl mode for spectre_v2_user
    (bnc#1012382).

  - x86/speculation/l1tf: Document l1tf in sysfs
    (bnc#1012382).

  - x86/speculation: Mark string arrays const correctly
    (bnc#1012382).

  - x86/speculation/mds: Fix comment (bnc#1012382).

  - x86/speculation/mds: Fix documentation typo
    (bnc#1012382).

  - x86/speculation: Move STIPB/IBPB string conditionals out
    of cpu_show_common() (bnc#1012382).

  - x86/speculation: Prepare arch_smt_update() for PRCTL
    mode (bnc#1012382).

  - x86/speculation: Prepare for conditional IBPB in
    switch_mm() (bnc#1012382).

  - x86/speculation: Prepare for per task indirect branch
    speculation control (bnc#1012382).

  - x86/speculation: Prevent stale SPEC_CTRL msr content
    (bnc#1012382).

  - x86/speculation: Provide IBPB always command line
    options (bnc#1012382).

  - x86/speculation: Remove SPECTRE_V2_IBRS in enum
    spectre_v2_mitigation (bnc#1012382).

  - x86/speculation: Remove unnecessary ret variable in
    cpu_show_common() (bnc#1012382).

  - x86/speculation: Rename SSBD update functions
    (bnc#1012382).

  - x86/speculation: Reorder the spec_v2 code (bnc#1012382).

  - x86/speculation: Reorganize speculation control MSRs
    update (bnc#1012382).

  - x86/speculation: Split out TIF update (bnc#1012382).

  - x86/speculation: Support Enhanced IBRS on future CPUs
    (bnc#1012382).

  - x86/speculation: Support 'mitigations=' cmdline option
    (bnc#1012382 bsc#1112178).

  - x86/speculation: Unify conditional spectre v2 print
    functions (bnc#1012382).

  - x86/speculation: Update the TIF_SSBD comment
    (bnc#1012382).

  - xenbus: drop useless LIST_HEAD in xenbus_write_watch()
    and xenbus_file_write() (bsc#1065600).

  - xsysace: Fix error handling in ace_setup (bnc#1012382)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053043"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120642"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135281"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136810"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137162"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137915"
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.180-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.180-102.1") ) flag++;

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
