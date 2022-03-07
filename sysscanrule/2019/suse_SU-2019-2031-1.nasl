#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2031-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(127760);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2018-11782", "CVE-2019-0203");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : subversion (SUSE-SU-2019:2031-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for subversion to version 1.10.6 fixes the following
issues :

Security issues fixed :

CVE-2018-11782: Fixed a remote denial of service in svnserve
'get-deleted-rev' (bsc#1142743).

CVE-2019-0203: Fixed a remote, unauthenticated denial of service in
svnserve (bsc#1142721).

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1142721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1142743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-11782/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-0203/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192031-1/
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

SUSE Linux Enterprise Module for Server Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Server-Applications-15-SP1-2019-2031=1

SUSE Linux Enterprise Module for Server Applications 15:zypper in -t
patch SUSE-SLE-Module-Server-Applications-15-2019-2031=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-2031=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-2031=1

SUSE Linux Enterprise Module for Development Tools 15-SP1:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-SP1-2019-2031=1

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2019-2031=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-2031=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-2031=1"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsvn_auth_gnome_keyring-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsvn_auth_gnome_keyring-1-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:subversion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:subversion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:subversion-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:subversion-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:subversion-python-ctypes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:subversion-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:subversion-ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:subversion-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:subversion-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:subversion-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
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
if (os_ver == "SLES15" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-debugsource-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-server-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-server-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsvn_auth_gnome_keyring-1-0-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-debugsource-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-python-ctypes-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-ruby-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-ruby-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-debugsource-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-perl-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-perl-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-python-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-python-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-tools-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-tools-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-debugsource-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"subversion-devel-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-debugsource-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-server-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-server-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsvn_auth_gnome_keyring-1-0-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-debugsource-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-python-ctypes-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-ruby-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-ruby-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-debugsource-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-perl-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-perl-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-python-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-python-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-tools-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-tools-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-debugsource-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"subversion-devel-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsvn_auth_gnome_keyring-1-0-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"subversion-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"subversion-debugsource-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"subversion-python-ctypes-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"subversion-ruby-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"subversion-ruby-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"subversion-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"subversion-debugsource-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"subversion-perl-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"subversion-perl-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"subversion-python-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"subversion-python-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"subversion-tools-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"subversion-tools-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"subversion-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"subversion-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"subversion-debugsource-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"subversion-devel-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsvn_auth_gnome_keyring-1-0-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"subversion-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"subversion-debugsource-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"subversion-python-ctypes-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"subversion-ruby-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"subversion-ruby-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"subversion-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"subversion-debugsource-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"subversion-perl-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"subversion-perl-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"subversion-python-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"subversion-python-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"subversion-tools-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"subversion-tools-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"subversion-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"subversion-debuginfo-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"subversion-debugsource-1.10.6-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"subversion-devel-1.10.6-3.6.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "subversion");
}
