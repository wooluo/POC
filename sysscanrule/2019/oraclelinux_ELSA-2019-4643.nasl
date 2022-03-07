#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-4643.
#

include("compat.inc");

if (description)
{
  script_id(125236);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/24  9:40:20");

  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-19985", "CVE-2019-10124", "CVE-2019-11091");

  script_name(english:"Oracle Linux 7 : Unbreakable Enterprise kernel (ELSA-2019-4643) (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[4.14.35-1844.5.3.el7uek]
- x86/mds: Add empty commit for CVE-2019-11091 (Konrad Rzeszutek Wilk)  [Orabug: 29721848]  {CVE-2019-11091}
- x86/speculation/mds: Make mds_mitigation mutable after init (Konrad Rzeszutek Wilk)  [Orabug: 29721835]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}

[4.14.35-1844.5.2.el7uek]
- xen: Fix x86 sched_clock() interface for xen (Juergen Gross)  [Orabug: 29464437]
- x86/xen/time: Output xen sched_clock time from 0 (Pavel Tatashin)  [Orabug: 29464437]
- repairing kmodstd to support cross compilation (Mark Nicholson)  [Orabug: 29682406]
- xfs: don't overflow xattr listent buffer (Darrick J. Wong)  [Orabug: 29697225]

[4.14.35-1844.5.1.el7uek]
- x86/speculation: Support 'mitigations=' cmdline option (Josh Poimboeuf)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- cpu/speculation: Add 'mitigations=' cmdline option (Josh Poimboeuf)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Print SMT vulnerable on MSBDS with mitigations off (Konrad Rzeszutek Wilk)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Fix comment (Boris Ostrovsky)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add debugfs for controlling MDS (Kanth Ghatraju)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add boot option to enable MDS protection only while in idle (Boris Ostrovsky)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add SMT warning message (Josh Poimboeuf)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation: Move arch_smt_update() call to after mitigation decisions (Josh Poimboeuf)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add mds=full,nosmt cmdline option (Josh Poimboeuf)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- Documentation: Add MDS vulnerability documentation (Thomas Gleixner)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- Documentation: Move L1TF to separate directory (Thomas Gleixner)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add mitigation mode VMWERV (Thomas Gleixner)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add sysfs reporting for MDS (Thomas Gleixner)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add mitigation control for MDS (Thomas Gleixner)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Conditionally clear CPU buffers on idle entry (Thomas Gleixner)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/kvm/vmx: Add MDS protection when L1D Flush is not active (Thomas Gleixner)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Clear CPU buffers on exit to user (Thomas Gleixner)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add mds_clear_cpu_buffers() (Thomas Gleixner)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/kvm: Expose X86_FEATURE_MD_CLEAR to guests (Andi Kleen)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add BUG_MSBDS_ONLY (Thomas Gleixner)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add basic bug infrastructure for MDS (Andi Kleen)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127} {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation: Consolidate CPU whitelists (Thomas Gleixner)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/msr-index: Cleanup bit defines (Thomas Gleixner)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
file (Will Deacon)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/cpu: Sanitize FAM6_ATOM naming (Peter Zijlstra)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- Documentation/l1tf: Fix small spelling typo (Salvatore Bonaccorso)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation: Simplify the CPU bug detection logic (Dominik Brodowski)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- tools include: Adopt linux/bits.h (Arnaldo Carvalho de Melo)  [Orabug: 29526899]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}

[4.14.35-1844.5.0.el7uek]
- swiotlb: save io_tlb_used to local variable before leaving critical section (Dongli Zhang)  [Orabug: 29637519]
- swiotlb: dump used and total slots when swiotlb buffer is full (Dongli Zhang)  [Orabug: 29637519]
- bonding: ratelimit no-delay interface up messages (Shamir Rabinovitch)  [Orabug: 29016284]
- xen/netfront: don't bug in case of too many frags (Juergen Gross)  [Orabug: 29462653]
- bnxt_en: Drop oversize TX packets to prevent errors. (Michael Chan)  [Orabug: 29547792]
- xen/netfront: tolerate frags with no data (Juergen Gross)  [Orabug: 29632146]
- net/mlx5: E-Switch, fix syndrome (0x678139) when turn on vepa (Huy Nguyen)  [Orabug: 29455439]
- net/mlx5: E-Switch, Fix access to invalid memory when toggling esw modes (Roi Dayan)  [Orabug: 29455439]
- net/mlx5: Avoid panic when setting vport mac, getting vport config (Tonghao Zhang)  [Orabug: 29455439]
- net/mlx5: Support ndo bridge_setlink and getlink (Huy Nguyen)  [Orabug: 29455439]
- net/mlx5: E-Switch, Add support for VEPA in legacy mode. (Huy Nguyen)  [Orabug: 29455439]
- net/mlx5: Split FDB fast path prio to multiple namespaces (Paul Blakey)  [Orabug: 29455439]
- net/mlx5: E-Switch, Remove unused argument when creating legacy FDB (Eli Cohen)  [Orabug: 29455439]
- net/mlx5: E-switch, Create a second level FDB flow table (Chris Mi)  [Orabug: 29455439]
- net/mlx5: Add cap bits for flow table destination in FDB table (Chris Mi)  [Orabug: 29455439]
- net/mlx5: E-Switch, Reorganize and rename fdb flow tables (Chris Mi)  [Orabug: 29455439]
- net/mlx5: Add destination e-switch owner (Shahar Klein)  [Orabug: 29455439]
- net/mlx5: Properly handle a vport destination when setting FTE (Shahar Klein)  [Orabug: 29455439]
- net/mlx5: E-Switch, Reload IB interface when switching devlink modes (Mark Bloch)  [Orabug: 29455439]
- net/mlx5: E-Switch, Optimize HW steering tables in switchdev mode (Mark Bloch)  [Orabug: 29455439]
- net/mlx5: E-Switch, Increase number of FTEs in FDB in switchdev mode (Mark Bloch)  [Orabug: 29455439]
- net/mlx5: Separate ingress/egress namespaces for each vport (Gal Pressman)  [Orabug: 29455439]
- net/mlx5: Fix ingress/egress naming mistake (Gal Pressman)  [Orabug: 29455439]
- net/mlx5: Initialize destination_flow struct to 0 (Rabie Loulou)  [Orabug: 29455439]
- USB: hso: Fix OOB memory access in hso_probe/hso_get_config_data (Hui Peng)  [Orabug: 29613788]  {CVE-2018-19985} {CVE-2018-19985}
- mm: hwpoison: fix thp split handing in soft_offline_in_use_page() (zhongjiang)  [Orabug: 29613794]  {CVE-2019-10124}
- x86/bugs, kvm: don't miss SSBD when IBRS is in use. (Mihai Carabas)  [Orabug: 29642112]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-May/008741.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/17");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-19985", "CVE-2019-10124", "CVE-2019-11091");  
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for ELSA-2019-4643");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

kernel_major_minor = get_kb_item("Host/uname/major_minor");
if (empty_or_null(kernel_major_minor)) exit(1, "Unable to determine kernel major-minor level.");
expected_kernel_major_minor = "4.14";
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, "running kernel level " + expected_kernel_major_minor + ", it is running kernel level " + kernel_major_minor);

flag = 0;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-4.14.35-1844.5.3.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-4.14.35-1844.5.3.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-devel-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.14.35-1844.5.3.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-devel-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-devel-4.14.35-1844.5.3.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-doc-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-doc-4.14.35-1844.5.3.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-tools-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-tools-4.14.35-1844.5.3.el7uek")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
