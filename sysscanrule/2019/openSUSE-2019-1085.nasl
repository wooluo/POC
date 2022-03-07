#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1085.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(123545);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/24 10:35:07");

  script_cve_id("CVE-2019-2024", "CVE-2019-9213");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-1085)");
  script_summary(english:"Check for the openSUSE-2019-1085 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 kernel was updated to 4.4.176 to receive
various security and bugfixes.

The following security bugs were fixed :

  - CVE-2019-9213: expand_downwards in mm/mmap.c lacked a
    check for the mmap minimum address, which made it easier
    for attackers to exploit kernel NULL pointer
    dereferences on non-SMAP platforms. This is related to a
    capability check for the wrong task (bnc#1128166).

  - CVE-2019-2024: A use-after-free when disconnecting a
    source was fixed which could lead to crashes.
    bnc#1129179).

The following non-security bugs were fixed :

  - ax25: fix possible use-after-free (bnc#1012382).

  - block_dev: fix crash on chained bios with O_DIRECT
    (bsc#1090435).

  - block: do not use bio->bi_vcnt to figure out segment
    number (bsc#1128893).

  - bnxt_re: Fix couple of memory leaks that could lead to
    IOMMU call traces (bsc#1020413).

  - bpf: fix replace_map_fd_with_map_ptr's ldimm64 second
    imm field (bsc#1012382).

  - btrfs: ensure that a DUP or RAID1 block group has
    exactly two stripes (bsc#1128452).

  - ceph: avoid repeatedly adding inode to
    mdsc->snap_flush_list (bsc#1126773).

  - ch: add missing mutex_lock()/mutex_unlock() in
    ch_release() (bsc#1124235).

  - ch: fixup refcounting imbalance for SCSI devices
    (bsc#1124235).

  - copy_mount_string: Limit string length to PATH_MAX
    (bsc#1082943).

  - device property: Fix the length used in
    PROPERTY_ENTRY_STRING() (bsc#1129770).

  - Drivers: hv: vmbus: Check for ring when getting debug
    info (bsc#1126389).

  - drm: Fix error handling in drm_legacy_addctx
    (bsc#1106929)

  - drm/nouveau/bios/ramcfg: fix missing parentheses when
    calculating RON (bsc#1106929)

  - drm/nouveau/pmu: do not print reply values if exec is
    false (bsc#1106929)

  - drm/radeon/evergreen_cs: fix missing break in switch
    statement (bsc#1106929)

  - drm/vmwgfx: Do not double-free the mode stored in
    par->set_mode (bsc#1103429)

  - enic: add wq clean up budget (bsc#1075697, bsc#1120691.
    bsc#1102959).

  - enic: do not overwrite error code (bnc#1012382).

  - fbdev: chipsfb: remove set but not used variable 'size'
    (bsc#1106929)

  - ibmvnic: Report actual backing device speed and duplex
    values (bsc#1129923).

  - ibmvscsi: Fix empty event pool access during host
    removal (bsc#1119019).

  - Input: mms114 - fix license module information
    (bsc#1087092).

  - iommu/dmar: Fix buffer overflow during PCI bus
    notification (bsc#1129237).

  - iommu/io-pgtable-arm-v7s: Only kmemleak_ignore L2 tables
    (bsc#1129238).

  - iommu/vt-d: Check identity map for hot-added devices
    (bsc#1129239).

  - iommu/vt-d: Fix NULL pointer reference in
    intel_svm_bind_mm() (bsc#1129240).

  - ixgbe: fix crash in build_skb Rx code path (git-fixes).

  - kABI: protect struct inet_peer (kabi).

  - kallsyms: Handle too long symbols in kallsyms.c
    (bsc#1126805).

  - KMPs: obsolete older KMPs of the same flavour
    (bsc#1127155, bsc#1109137).

  - KVM: arm/arm64: vgic-its: Check CBASER/BASER validity
    before enabling the ITS (bsc#1109248).

  - KVM: arm/arm64: vgic-its: Check GITS_BASER Valid bit
    before saving tables (bsc#1109248).

  - KVM: arm/arm64: vgic-its: Fix return value for device
    table restore (bsc#1109248).

  - KVM: arm/arm64: vgic-its: Fix
    vgic_its_restore_collection_table returned value
    (bsc#1109248).

  - kvm: nVMX: Do not halt vcpu when L1 is injecting events
    to L2 (bsc#1129413).

  - kvm: nVMX: Free the VMREAD/VMWRITE bitmaps if
    alloc_kvm_area() fails (bsc#1129414).

  - kvm: nVMX: NMI-window and interrupt-window exiting
    should wake L2 from HLT (bsc#1129415).

  - kvm: nVMX: Set VM instruction error for VMPTRLD of
    unbacked page (bsc#1129416).

  - kvm: VMX: Do not allow reexecute_instruction() when
    skipping MMIO instr (bsc#1129417).

  - kvm: vmx: Set IA32_TSC_AUX for legacy mode guests
    (bsc#1129418).

  - kvm: x86: Add AMD's EX_CFG to the list of ignored MSRs
    (bsc#1127082).

  - kvm: x86: IA32_ARCH_CAPABILITIES is always supported
    (bsc#1129419).

  - libceph: handle an empty authorize reply (bsc#1126772).

  - mdio_bus: Fix use-after-free on device_register fails
    (git-fixes).

  - mfd: as3722: Handle interrupts on suspend (bnc#1012382).

  - mfd: as3722: Mark PM functions as __maybe_unused
    (bnc#1012382).

  - mISDN: fix a race in dev_expire_timer() (bnc#1012382).

  - mlxsw: pci: Correctly determine if descriptor queue is
    full (git-fixes).

  - mlxsw: reg: Use correct offset in field definiton
    (git-fixes).

  - mm, devm_memremap_pages: mark devm_memremap_pages()
    EXPORT_SYMBOL_GPL (bnc#1012382).

  - mm,memory_hotplug: fix scan_movable_pages() for gigantic
    hugepages (bsc#1127731).

  - net: Add header for usage of fls64() (bnc#1012382).

  - net: Do not allocate page fragments that are not skb
    aligned (bnc#1012382).

  - net: dsa: bcm_sf2: Do not assume DSA master supports WoL
    (git-fixes).

  - net: dsa: mv88e6xxx: fix port VLAN maps (git-fixes).

  - net: Fix for_each_netdev_feature on Big endian
    (bnc#1012382).

  - net: fix IPv6 prefix route residue (bnc#1012382).

  - net/hamradio/6pack: Convert timers to use timer_setup()
    (git-fixes).

  - net/hamradio/6pack: use mod_timer() to rearm timers
    (git-fixes).

  - net: ipv4: use a dedicated counter for icmp_v4 redirect
    packets (bnc#1012382).

  - net: lan78xx: Fix race in tx pending skb size
    calculation (git-fixes).

  - net/mlx4_core: drop useless LIST_HEAD (git-fixes).

  - net/mlx4_core: Fix qp mtt size calculation (git-fixes).

  - net/mlx4_core: Fix reset flow when in command polling
    mode (git-fixes).

  - net/mlx4: Fix endianness issue in qp context params
    (git-fixes).

  - net/mlx5: Continue driver initialization despite debugfs
    failure (git-fixes).

  - net/mlx5e: Fix TCP checksum in LRO buffers (git-fixes).

  - net/mlx5: Fix driver load bad flow when having fw
    initializing timeout (git-fixes).

  - net/mlx5: fix uaccess beyond 'count' in debugfs
    read/write handlers (git-fixes).

  - net/mlx5: Fix use-after-free in self-healing flow
    (git-fixes).

  - net/mlx5: Return success for PAGE_FAULT_RESUME in
    internal error state (git-fixes).

  - net: mv643xx_eth: fix packet corruption with TSO and
    tiny unaligned packets (git-fixes).

  - net: phy: Avoid polling PHY with PHY_IGNORE_INTERRUPTS
    (git-fixes).

  - net: phy: bcm7xxx: Fix shadow mode 2 disabling
    (git-fixes).

  - net: qca_spi: Fix race condition in spi transfers
    (git-fixes).

  - net: stmmac: Fix a race in EEE enable callback
    (bnc#1012382).

  - net: stmmac: Fix a race in EEE enable callback
    (git-fixes).

  - net: thunderx: set tso_hdrs pointer to NULL in
    nicvf_free_snd_queue (git-fixes).

  - net/x25: do not hold the cpu too long in x25_new_lci()
    (bnc#1012382).

  - pci/pme: Fix hotplug/sysfs remove deadlock in
    pcie_pme_remove() (bsc#1129241).

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

  - phy: micrel: Ensure interrupts are reenabled on resume
    (git-fixes).

  - powerpc/pseries: Add CPU dlpar remove functionality
    (bsc#1128756).

  - powerpc/pseries: Consolidate CPU hotplug code to
    hotplug-cpu.c (bsc#1128756).

  - powerpc/pseries: Factor out common cpu hotplug code
    (bsc#1128756).

  - powerpc/pseries: Perform full re-add of CPU for topology
    update post-migration (bsc#1128756).

  - pppoe: fix reception of frames with no mac header
    (git-fixes).

  - pptp: dst_release sk_dst_cache in pptp_sock_destruct
    (git-fixes).

  - pseries/energy: Use OF accessor function to read
    ibm,drc-indexes (bsc#1129080).

  - RDMA/bnxt_re: Synchronize destroy_qp with poll_cq
    (bsc#1125446).

  - Refresh
    patches.suse/scsi-do-not-print-reservation-conflict-for-
    TEST-UNIT.patch (bsc#1119843)

  - Revert 'mm, devm_memremap_pages: mark
    devm_memremap_pages() EXPORT_SYMBOL_GPL' (bnc#1012382).

  - Revert 'x86/platform/UV: Use efi_runtime_lock to
    serialise BIOS calls' (bsc#1128565).

  - s390/qeth: cancel close_dev work before removing a card
    (LTC#175898, bsc#1127561).

  - scsi: aacraid: Fix missing break in switch statement
    (bsc#1128696).

  - scsi: ibmvscsi: Fix empty event pool access during host
    removal (bsc#1119019).

  - scsi: lpfc: do not set queue->page_count to 0 if
    pc_sli4_params.wqpcnt is invalid (bsc#1127725).

  - scsi: qla2xxx: Fix early srb free on abort
    (bsc#1121713).

  - scsi: qla2xxx: Fix for double free of SRB structure
    (bsc#1121713).

  - scsi: qla2xxx: Increase abort timeout value
    (bsc#1121713).

  - scsi: qla2xxx: Move {get|rel}_sp to base_qpair struct
    (bsc#1121713).

  - scsi: qla2xxx: Return switch command on a timeout
    (bsc#1121713).

  - scsi: qla2xxx: Turn off IOCB timeout timer on IOCB
    completion (bsc#1121713).

  - scsi: qla2xxx: Use correct qpair for ABTS/CMD
    (bsc#1121713).

  - scsi: sym53c8xx: fix NULL pointer dereference panic in
    sym_int_sir() (bsc#1125315).

  - sky2: Increase D3 delay again (bnc#1012382).

  - tcp: clear icsk_backoff in tcp_write_queue_purge()
    (bnc#1012382).

  - tcp: tcp_v4_err() should be more careful (bnc#1012382).

  - team: avoid complex list operations in
    team_nl_cmd_options_set() (bnc#1012382).

  - team: Free BPF filter when unregistering netdev
    (git-fixes).

  - tracing: Do not free iter->trace in fail path of
    tracing_open_pipe() (bsc#1129581).

  - vsock: cope with memory allocation failure at socket
    creation time (bnc#1012382).

  - vxlan: test dev->flags & IFF_UP before calling
    netif_rx() (bnc#1012382).

  - wireless: airo: potential buffer overflow in sprintf()
    (bsc#1120902).

  - x86: Add TSX Force Abort CPUID/MSR (bsc#1121805).

  - x86: livepatch: Treat R_X86_64_PLT32 as R_X86_64_PC32
    (bnc#1012382).

  - xen, cpu_hotplug: Prevent an out of bounds access
    (bsc#1065600).

  - xen: remove pre-xen3 fallback handlers (bsc#1065600).

  - xfs: remove filestream item xfs_inode reference
    (bsc#1127961)."
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129581"
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
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/01");
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

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.176-96.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.176-96.1") ) flag++;

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
