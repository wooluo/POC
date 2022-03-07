#
# (C) WebRAY Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2019-0002.
#

include("compat.inc");

if (description)
{
  script_id(121605);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/02 21:54:17");

  script_cve_id("CVE-2017-17450", "CVE-2017-18079", "CVE-2017-18174", "CVE-2017-18221", "CVE-2017-18255", "CVE-2017-9725", "CVE-2018-1092", "CVE-2018-1094", "CVE-2018-18397", "CVE-2018-19824", "CVE-2018-5848", "CVE-2018-7995", "CVE-2018-9363", "CVE-2018-9516", "CVE-2019-5489");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2019-0002)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - rds: congestion updates can be missed when kernel low on
    memory (Mukesh Kacker) [Orabug: 28425811]

  - net/rds: ib: Fix endless RNR Retries caused by memory
    allocation failures (Venkat Venkatsubra) [Orabug:
    28127993]

  - net: rds: fix excess initialization of the recv SGEs
    (Zhu Yanjun) [Orabug: 29004503]

  - xhci: fix usb2 resume timing and races. (Mathias Nyman)
    [Orabug: 29028940]

  - xhci: Fix a race in usb2 LPM resume, blocking U3 for
    usb2 devices (Mathias Nyman) [Orabug: 29028940]

  - userfaultfd: check VM_MAYWRITE was set after verifying
    the uffd is registered (Andrea Arcangeli) [Orabug:
    29163750] (CVE-2018-18397)

  - userfaultfd: shmem/hugetlbfs: only allow to register
    VM_MAYWRITE vmas (Andrea Arcangeli) [Orabug: 29163750]
    (CVE-2018-18397)

  - x86/apic/x2apic: set affinity of a single interrupt to
    one cpu (Jianchao Wang) [Orabug: 29196396]

  - xen/blkback: rework validate_io_op (Dongli Zhang)
    [Orabug: 29199843]

  - xen/blkback: optimize validate_io_op to filter
    BLKIF_OP_RESERVED_1 operation (Dongli Zhang) [Orabug:
    29199843]

  - xen/blkback: do not BUG for invalid blkif_request from
    frontend (Dongli Zhang) [Orabug: 29199843]

  - net/rds: WARNING: at net/rds/recv.c:222
    rds_recv_hs_exthdrs+0xf8/0x1e0 (Venkat Venkatsubra)
    [Orabug: 29201779]

  - xen-netback: wake up xenvif_dealloc_kthread when it
    should stop (Dongli Zhang) [Orabug: 29217927]

  - Revert 'xfs: remove nonblocking mode from
    xfs_vm_writepage' (Wengang Wang) [Orabug: 29279692]

  - Revert 'xfs: remove xfs_cancel_ioend' (Wengang Wang)
    [Orabug: 29279692]

  - Revert 'xfs: Introduce writeback context for writepages'
    (Wengang Wang) [Orabug: 29279692]

  - Revert 'xfs: xfs_cluster_write is redundant' (Wengang
    Wang) [Orabug: 29279692]

  - Revert 'xfs: factor mapping out of xfs_do_writepage'
    (Wengang Wang) [Orabug: 29279692]

  - Revert 'xfs: don't chain ioends during writepage
    submission' (Wengang Wang) [Orabug: 29279692]

  - mstflint: Fix coding style issues - left with
    LINUX_VERSION_CODE (Idan Mehalel) [Orabug: 28878697]

  - mstflint: Fix coding-style issues (Idan Mehalel)
    [Orabug: 28878697]

  - mstflint: Fix errors found with checkpatch script (Idan
    Mehalel) [Orabug: 28878697]

  - Added support for 5th Gen devices in Secure Boot module
    and mtcr (Adham Masarwah) [Orabug: 28878697]

  - Fix typos in mst_kernel (Adham Masarwah) [Orabug:
    28878697]

  - bnxt_en: Report PCIe link properties with
    pcie_print_link_status (Brian Maly) [Orabug: 28942099]

  - selinux: Perform both commoncap and selinux xattr checks
    (Eric W. Biederman) [Orabug: 28951521]

  - Introduce v3 namespaced file capabilities (Serge E.
    Hallyn) [Orabug: 28951521]

  - rds: ib: Use a delay when reconnecting to the very same
    IP address (H&aring kon Bugge) [Orabug: 29138813]

  - Change mincore to count 'mapped' pages rather than
    'cached' pages (Linus Torvalds) [Orabug: 29187415]
    (CVE-2019-5489)

  - NFSD: Set the attributes used to store the verifier for
    EXCLUSIVE4_1 (Kinglong Mee) [Orabug: 29204157]

  - ext4: update i_disksize when new eof exceeds it (Shan
    Hai) [Orabug: 28940828]

  - ext4: update i_disksize if direct write past ondisk size
    (Eryu Guan) [Orabug: 28940828]

  - ext4: protect i_disksize update by i_data_sem in direct
    write path (Eryu Guan) [Orabug: 28940828]

  - ALSA: usb-audio: Fix UAF decrement if card has no live
    interfaces in card.c (Hui Peng) [Orabug: 29042981]
    (CVE-2018-19824)

  - ALSA: usb-audio: Replace probing flag with active
    refcount (Takashi Iwai) [Orabug: 29042981]
    (CVE-2018-19824)

  - ALSA: usb-audio: Avoid nested autoresume calls (Takashi
    Iwai) [Orabug: 29042981] (CVE-2018-19824)

  - ext4: validate that metadata blocks do not overlap
    superblock (Theodore Ts'o) [Orabug: 29114440]
    (CVE-2018-1094)

  - ext4: update inline int ext4_has_metadata_csum(struct
    super_block *sb) (John Donnelly) [Orabug: 29114440]
    (CVE-2018-1094)

  - ext4: always initialize the crc32c checksum driver
    (Theodore Ts'o) [Orabug: 29114440] (CVE-2018-1094)
    (CVE-2018-1094)

  - Revert 'bnxt_en: Reduce default rings on multi-port
    cards.' (Brian Maly) [Orabug: 28687746]

  - mlx4_core: Disable P_Key Violation Traps (H&aring kon
    Bugge) [Orabug: 27693633]

  - rds: RDS connection does not reconnect after CQ access
    violation error (Venkat Venkatsubra) [Orabug: 28733324]

  - KVM/SVM: Allow direct access to MSR_IA32_SPEC_CTRL
    (KarimAllah Ahmed) [Orabug: 28069548]

  - KVM/VMX: Allow direct access to MSR_IA32_SPEC_CTRL -
    reloaded (Mihai Carabas) [Orabug: 28069548]

  - KVM/x86: Add IBPB support (Ashok Raj) [Orabug: 28069548]

  - KVM: x86: pass host_initiated to functions that read
    MSRs (Paolo Bonzini) [Orabug: 28069548]

  - KVM: VMX: make MSR bitmaps per-VCPU (Paolo Bonzini)
    [Orabug: 28069548]

  - KVM: VMX: introduce alloc_loaded_vmcs (Paolo Bonzini)
    [Orabug: 28069548]

  - KVM: nVMX: Eliminate vmcs02 pool (Jim Mattson) [Orabug:
    28069548]

  - KVM: nVMX: fix msr bitmaps to prevent L2 from accessing
    L0 x2APIC (Radim Kr&#x10D m&aacute &#x159 ) [Orabug:
    28069548]

  - ocfs2: don't clear bh uptodate for block read (Junxiao
    Bi) [Orabug: 28762940]

  - ocfs2: clear journal dirty flag after shutdown journal
    (Junxiao Bi) [Orabug: 28924775]

  - ocfs2: fix panic due to unrecovered local alloc (Junxiao
    Bi) [Orabug: 28924775]

  - net: rds: fix rds_ib_sysctl_max_recv_allocation error
    (Zhu Yanjun) [Orabug: 28947481]

  - x86/speculation: Always disable IBRS in
    disable_ibrs_and_friends (Alejandro Jimenez) [Orabug:
    29139710]

  - pinctrl: amd: Use devm_pinctrl_register for pinctrl
    registration (Laxman Dewangan) [Orabug: 27539246]
    (CVE-2017-18174)

  - mlock: fix mlock count can not decrease in race
    condition (Yisheng Xie) [Orabug: 27677611]
    (CVE-2017-18221)

  - perf/core: Fix the perf_cpu_time_max_percent check (Tan
    Xiaojun) [Orabug: 27823815] (CVE-2017-18255)

  - x86/microcode/intel: Fix a wrong assignment of revision
    in _save_mc (Zhenzhong Duan) [Orabug: 28190263]

  - mm: cma: fix incorrect type conversion for size during
    dma allocation (Rohit Vaswani) [Orabug: 28407826]
    (CVE-2017-9725)

  - x86/speculation: Make enhanced IBRS the default spectre
    v2 mitigation (Alejandro Jimenez) [Orabug: 28474851]

  - x86/speculation: Enable enhanced IBRS usage (Alejandro
    Jimenez) [Orabug: 28474851]

  - x86/speculation: functions for supporting enhanced IBRS
    (Alejandro Jimenez) [Orabug: 28474851]

  - xen/blkback: fix disconnect while I/Os in flight
    (Juergen Gross) [Orabug: 28744234]

  - mlx4_vnic: use the mlid while calling ib_detach_mcast
    (aru kolappan) [Orabug: 29029705]

  - ext4: fail ext4_iget for root directory if unallocated
    (Theodore Ts'o) [Orabug: 29048557] (CVE-2018-1092)
    (CVE-2018-1092)

  - Bluetooth: hidp: buffer overflow in hidp_process_report
    (Mark Salyzyn) [Orabug: 29121215] (CVE-2018-9363)
    (CVE-2018-9363)

  - HID: debug: check length before copy_to_user (Daniel
    Rosenberg) [Orabug: 29128165] (CVE-2018-9516)

  - x86/MCE: Serialize sysfs changes (Seunghun Han) [Orabug:
    29149888] (CVE-2018-7995)

  - Input: i8042 - fix crash at boot time (Chen Hong)
    [Orabug: 29152328] (CVE-2017-18079)

  - base/memory, hotplug: fix a kernel oops in
    show_valid_zones (Toshi Kani) [Orabug: 29050538]

  - mm/memory_hotplug.c: check start_pfn in
    test_pages_in_a_zone (Toshi Kani) [Orabug: 29050538]

  - drivers/base/memory.c: prohibit offlining of memory
    blocks with missing sections (Seth Jennings) [Orabug:
    29050538]

  - mm: Check if section present during memory block
    (un)registering (Yinghai Lu) [Orabug: 29050538]

  - hugetlb: take PMD sharing into account when flushing
    tlb/caches (Mike Kravetz) [Orabug: 28951854]

  - mm: migration: fix migration of huge PMD shared pages
    (Mike Kravetz) [Orabug: 28951854]

  - hugetlbfs: use truncate mutex to prevent pmd sharing
    race (Mike Kravetz) [Orabug: 28896255]

  - rds: ib: Improve tracing during failover/back
    (H&aring kon Bugge) [Orabug: 28860366]

  - rds: ib: Remove superfluous add of address on fail-back
    device (H&aring kon Bugge) [Orabug: 28860366]

  - libiscsi: Fix NULL pointer dereference in
    iscsi_eh_session_reset (Fred Herard) [Orabug: 28946207]

  - wil6210: missing length check in wmi_set_ie (Lior David)
    [Orabug: 28951265] (CVE-2018-5848)

  - netfilter: xt_osf: Add missing permission checks (Kevin
    Cernekee) [Orabug: 29037831] (CVE-2017-17450)

  - x86/speculation: Fix bad argument to rdmsrl in
    cpu_set_bug_bits (Alejandro Jimenez) [Orabug: 29044805]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2019-February/000927.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.24.5.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.24.5.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
