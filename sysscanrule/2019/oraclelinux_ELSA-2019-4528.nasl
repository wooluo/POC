#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-4528.
#

include("compat.inc");

if (description)
{
  script_id(121566);
  script_version("1.7");
  script_cvs_date("Date: 2019/07/24  9:40:20");

  script_cve_id("CVE-2018-18397", "CVE-2019-5489");

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2019-4528)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[4.1.12-124.24.5.el7uek]
- rds: congestion updates can be missed when kernel low on memory (Mukesh Kacker)  [Orabug: 28425811]
- net/rds: ib: Fix endless RNR Retries caused by memory allocation failures (Venkat Venkatsubra)  [Orabug: 28127993]
- net: rds: fix excess initialization of the recv SGEs (Zhu Yanjun)  [Orabug: 29004503]
- xhci: fix usb2 resume timing and races. (Mathias Nyman)  [Orabug: 29028940]
- xhci: Fix a race in usb2 LPM resume, blocking U3 for usb2 devices (Mathias Nyman)  [Orabug: 29028940]
- userfaultfd: check VM_MAYWRITE was set after verifying the uffd is registered (Andrea Arcangeli)  [Orabug: 29163750]  {CVE-2018-18397}
- userfaultfd: shmem/hugetlbfs: only allow to register VM_MAYWRITE vmas (Andrea Arcangeli)  [Orabug: 29163750]  {CVE-2018-18397}
- x86/apic/x2apic: set affinity of a single interrupt to one cpu (Jianchao Wang)  [Orabug: 29196396]
- xen/blkback: rework validate_io_op() (Dongli Zhang)  [Orabug: 29199843]
- xen/blkback: optimize validate_io_op() to filter BLKIF_OP_RESERVED_1 operation (Dongli Zhang)  [Orabug: 29199843]
- xen/blkback: do not BUG() for invalid blkif_request from frontend (Dongli Zhang)  [Orabug: 29199843]
- net/rds: WARNING: at net/rds/recv.c:222 rds_recv_hs_exthdrs+0xf8/0x1e0 (Venkat Venkatsubra)  [Orabug: 29201779]
- xen-netback: wake up xenvif_dealloc_kthread when it should stop (Dongli Zhang)  [Orabug: 29217927]
- Revert 'xfs: remove nonblocking mode from xfs_vm_writepage' (Wengang Wang)  [Orabug: 29279692]
- Revert 'xfs: remove xfs_cancel_ioend' (Wengang Wang)  [Orabug: 29279692]
- Revert 'xfs: Introduce writeback context for writepages' (Wengang Wang)  [Orabug: 29279692]
- Revert 'xfs: xfs_cluster_write is redundant' (Wengang Wang)  [Orabug: 29279692]
- Revert 'xfs: factor mapping out of xfs_do_writepage' (Wengang Wang)  [Orabug: 29279692]
- Revert 'xfs: don't chain ioends during writepage submission' (Wengang Wang)  [Orabug: 29279692]

[4.1.12-124.24.4.el7uek]
- mstflint: Fix coding style issues - left with LINUX_VERSION_CODE (Idan Mehalel)  [Orabug: 28878697]
- mstflint: Fix coding-style issues (Idan Mehalel)  [Orabug: 28878697]
- mstflint: Fix errors found with checkpatch script (Idan Mehalel)  [Orabug: 28878697]
- Added support for 5th Gen devices in Secure Boot module and mtcr (Adham Masarwah)  [Orabug: 28878697]
- Fix typos in mst_kernel (Adham Masarwah)  [Orabug: 28878697]
- bnxt_en: Report PCIe link properties with pcie_print_link_status() (Brian Maly)  [Orabug: 28942099]
- selinux: Perform both commoncap and selinux xattr checks (Eric W. Biederman)  [Orabug: 28951521]
- Introduce v3 namespaced file capabilities (Serge E. Hallyn)  [Orabug: 28951521]
- rds: ib: Use a delay when reconnecting to the very same IP address (H&aring kon Bugge)  [Orabug: 29138813]
- Change mincore() to count 'mapped' pages rather than 'cached' pages (Linus Torvalds)  [Orabug: 29187415]  {CVE-2019-5489}
- NFSD: Set the attributes used to store the verifier for EXCLUSIVE4_1 (Kinglong Mee)  [Orabug: 29204157]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-February/008461.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-February/008462.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");
include("ksplice.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2018-18397", "CVE-2019-5489");  
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for ELSA-2019-4528");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

kernel_major_minor = get_kb_item("Host/uname/major_minor");
if (empty_or_null(kernel_major_minor)) exit(1, "Unable to determine kernel major-minor level.");
expected_kernel_major_minor = "4.1";
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, "running kernel level " + expected_kernel_major_minor + ", it is running kernel level " + kernel_major_minor);

flag = 0;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-4.1.12-124.24.5.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-4.1.12-124.24.5.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.1.12-124.24.5.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-devel-4.1.12-124.24.5.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-doc-4.1.12-124.24.5.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-firmware-4.1.12-124.24.5.el6uek")) flag++;

if (rpm_exists(release:"EL7", rpm:"kernel-uek-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-4.1.12-124.24.5.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-4.1.12-124.24.5.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-devel-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.1.12-124.24.5.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-devel-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-devel-4.1.12-124.24.5.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-doc-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-doc-4.1.12-124.24.5.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-firmware-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-firmware-4.1.12-124.24.5.el7uek")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
