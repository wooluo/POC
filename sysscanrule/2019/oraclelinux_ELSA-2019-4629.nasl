#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-4629.
#

include("compat.inc");

if (description)
{
  script_id(125114);
  script_version("1.4");
  script_cvs_date("Date: 2019/07/24  9:40:20");

  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091");

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2019-4629) (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[4.1.12-124.26.12.el7uek]
- x86/mds: Add empty commit for CVE-2019-11091 (Konrad Rzeszutek Wilk)  [Orabug: 29721935]  {CVE-2019-11091}
- x86/microcode: Add loader version file in debugfs (Boris Ostrovsky)  [Orabug: 29754165]
- x86/microcode: Fix CPU synchronization routine (Borislav Petkov)  [Orabug: 29754165]
- x86/microcode: Synchronize late microcode loading (Borislav Petkov)  [Orabug: 29754165]

[4.1.12-124.26.11.el7uek]
- x86/speculation: Support 'mitigations=' cmdline option (Josh Poimboeuf)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- cpu/speculation: Add 'mitigations=' cmdline option (Josh Poimboeuf)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Print SMT vulnerable on MSBDS with mitigations off (Konrad Rzeszutek Wilk)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Fix comment (Boris Ostrovsky)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: update mds_mitigation to reflect debugfs configuration (Mihai Carabas)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: fix microcode late loading (Mihai Carabas)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add boot option to enable MDS protection only while in idle (Boris Ostrovsky)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Improve coverage for MDS vulnerability (Boris Ostrovsky)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add SMT warning message (Josh Poimboeuf)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add mds=full,nosmt cmdline option (Josh Poimboeuf)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- Documentation: Add MDS vulnerability documentation (Thomas Gleixner)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- Documentation: Move L1TF to separate directory (Thomas Gleixner)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add mitigation mode VMWERV (Thomas Gleixner)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add debugfs for controlling MDS (Kanth Ghatraju)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add sysfs reporting for MDS (Thomas Gleixner)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add mitigation control for MDS (Thomas Gleixner)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Conditionally clear CPU buffers on idle entry (Thomas Gleixner)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/kvm/vmx: Add MDS protection when L1D Flush is not active (Thomas Gleixner)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Clear CPU buffers on exit to user (Thomas Gleixner)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add mds_clear_cpu_buffers() (Thomas Gleixner)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/kvm: Expose X86_FEATURE_MD_CLEAR to guests (Andi Kleen)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add BUG_MSBDS_ONLY (Thomas Gleixner)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation/mds: Add basic bug infrastructure for MDS (Andi Kleen)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127} {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation: Consolidate CPU whitelists (Thomas Gleixner)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/msr-index: Cleanup bit defines (Thomas Gleixner)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- Documentation/l1tf: Fix small spelling typo (Salvatore Bonaccorso)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}
- x86/speculation: Simplify the CPU bug detection logic (Dominik Brodowski)  [Orabug: 29526900]  {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127}"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-May/008717.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-May/008718.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/15");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091");  
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for ELSA-2019-4629");
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
if (rpm_exists(release:"EL6", rpm:"kernel-uek-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-4.1.12-124.26.12.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-4.1.12-124.26.12.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.1.12-124.26.12.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-devel-4.1.12-124.26.12.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-doc-4.1.12-124.26.12.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-firmware-4.1.12-124.26.12.el6uek")) flag++;

if (rpm_exists(release:"EL7", rpm:"kernel-uek-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-4.1.12-124.26.12.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-4.1.12-124.26.12.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-devel-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.1.12-124.26.12.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-devel-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-devel-4.1.12-124.26.12.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-doc-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-doc-4.1.12-124.26.12.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-firmware-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-firmware-4.1.12-124.26.12.el7uek")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
