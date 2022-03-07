#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0527-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(122581);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/04  9:47:27");

  script_cve_id("CVE-2019-3825");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : gdm (SUSE-SU-2019:0527-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gdm fixes the following issues :

Security issue fixed :

CVE-2019-3825: Fixed a lock screen bypass when timed login was enabled
(bsc#1124628).

Other issues fixed: GLX applications do not work well when the
proprietary nvidia driver is used with a wayland session. Because of
that this update disables wayland on that hardware (bsc#1112578).

Fixed an issue where gdm restart fails to kill user processes
(bsc#1112294 and bsc#1113245).

Fixed a System halt in the screen with message 'End of ORACLE section'
(bsc#1120307).

Fixed an issue which did not allow the returning to text console when
gdm is stopped (bsc#1113700).

Fixed an issue which was causing system hang during the load of gdm
(bsc#1112578).

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1120307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1124628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3825/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190527-1/
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-527=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2019-527=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gdm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gdm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gdm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgdm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgdm1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-Gdm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", reference:"gdm-3.26.2.1-13.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gdm-debuginfo-3.26.2.1-13.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gdm-debugsource-3.26.2.1-13.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gdm-devel-3.26.2.1-13.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgdm1-3.26.2.1-13.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgdm1-debuginfo-3.26.2.1-13.19.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"typelib-1_0-Gdm-1_0-3.26.2.1-13.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gdm-3.26.2.1-13.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gdm-debuginfo-3.26.2.1-13.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gdm-debugsource-3.26.2.1-13.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gdm-devel-3.26.2.1-13.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgdm1-3.26.2.1-13.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgdm1-debuginfo-3.26.2.1-13.19.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"typelib-1_0-Gdm-1_0-3.26.2.1-13.19.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdm");
}
