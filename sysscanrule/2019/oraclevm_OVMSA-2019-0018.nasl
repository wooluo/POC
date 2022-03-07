#
# (C) WebRAY Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2019-0018.
#

include("compat.inc");

if (description)
{
  script_id(125105);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/16 10:38:54");

  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2019-0018) (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)");
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

  - x86/mds: Add empty commit for CVE-2019-11091 (Konrad
    Rzeszutek Wilk) [Orabug: 29721935] (CVE-2019-11091)

  - x86/microcode: Add loader version file in debugfs (Boris
    Ostrovsky) [Orabug: 29754165]

  - x86/microcode: Fix CPU synchronization routine (Borislav
    Petkov) [Orabug: 29754165]

  - x86/microcode: Synchronize late microcode loading
    (Borislav Petkov) [Orabug: 29754165]

  - x86/speculation: Support 'mitigations=' cmdline option
    (Josh Poimboeuf) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)

  - cpu/speculation: Add 'mitigations=' cmdline option (Josh
    Poimboeuf) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)

  - x86/speculation/mds: Print SMT vulnerable on MSBDS with
    mitigations off (Konrad Rzeszutek Wilk) [Orabug:
    29526900] (CVE-2018-12126) (CVE-2018-12130)
    (CVE-2018-12127)

  - x86/speculation/mds: Fix comment (Boris Ostrovsky)
    [Orabug: 29526900] (CVE-2018-12126) (CVE-2018-12130)
    (CVE-2018-12127)

  - x86/speculation/mds: update mds_mitigation to reflect
    debugfs configuration (Mihai Carabas) [Orabug: 29526900]
    (CVE-2018-12126) (CVE-2018-12130) (CVE-2018-12127)

  - x86/speculation/mds: fix microcode late loading (Mihai
    Carabas) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)

  - x86/speculation/mds: Add boot option to enable MDS
    protection only while in idle (Boris Ostrovsky) [Orabug:
    29526900] (CVE-2018-12126) (CVE-2018-12130)
    (CVE-2018-12127)

  - x86/speculation/mds: Improve coverage for MDS
    vulnerability (Boris Ostrovsky) [Orabug: 29526900]
    (CVE-2018-12126) (CVE-2018-12130) (CVE-2018-12127)

  - x86/speculation/mds: Add SMT warning message (Josh
    Poimboeuf) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)

  - x86/speculation/mds: Add mds=full,nosmt cmdline option
    (Josh Poimboeuf) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)

  - Documentation: Add MDS vulnerability documentation
    (Thomas Gleixner) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)

  - Documentation: Move L1TF to separate directory (Thomas
    Gleixner) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)

  - x86/speculation/mds: Add mitigation mode VMWERV (Thomas
    Gleixner) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)

  - x86/speculation/mds: Add debugfs for controlling MDS
    (Kanth Ghatraju) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)

  - x86/speculation/mds: Add sysfs reporting for MDS (Thomas
    Gleixner) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)

  - x86/speculation/mds: Add mitigation control for MDS
    (Thomas Gleixner) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)

  - x86/speculation/mds: Conditionally clear CPU buffers on
    idle entry (Thomas Gleixner) [Orabug: 29526900]
    (CVE-2018-12126) (CVE-2018-12130) (CVE-2018-12127)

  - x86/kvm/vmx: Add MDS protection when L1D Flush is not
    active (Thomas Gleixner) [Orabug: 29526900]
    (CVE-2018-12126) (CVE-2018-12130) (CVE-2018-12127)

  - x86/speculation/mds: Clear CPU buffers on exit to user
    (Thomas Gleixner) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)

  - x86/speculation/mds: Add mds_clear_cpu_buffers (Thomas
    Gleixner) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)

  - x86/kvm: Expose X86_FEATURE_MD_CLEAR to guests (Andi
    Kleen) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)

  - x86/speculation/mds: Add BUG_MSBDS_ONLY (Thomas
    Gleixner) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)

  - x86/speculation/mds: Add basic bug infrastructure for
    MDS (Andi Kleen) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127) (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)

  - x86/speculation: Consolidate CPU whitelists (Thomas
    Gleixner) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)

  - x86/msr-index: Cleanup bit defines (Thomas Gleixner)
    [Orabug: 29526900] (CVE-2018-12126) (CVE-2018-12130)
    (CVE-2018-12127)

  - Documentation/l1tf: Fix small spelling typo (Salvatore
    Bonaccorso) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)

  - x86/speculation: Simplify the CPU bug detection logic
    (Dominik Brodowski) [Orabug: 29526900] (CVE-2018-12126)
    (CVE-2018-12130) (CVE-2018-12127)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2019-May/000940.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.26.12.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.26.12.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
