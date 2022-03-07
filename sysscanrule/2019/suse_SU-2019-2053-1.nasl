#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2053-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(127768);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2018-1000802", "CVE-2018-14647", "CVE-2019-10160", "CVE-2019-9636");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : python3 (SUSE-SU-2019:2053-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for python3 fixes the following issues :

CVE-2019-10160: Fixed a regression in urlparse() and urlsplit()
introduced by the fix for CVE-2019-9636 (bsc#1138459).

CVE-2018-14647: Fixed a denial of service vulnerability caused by a
crafted XML document (bsc#1109847).

CVE-2018-1000802: Fixed a command injection in the shutil module
(bsc#1109663).

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1138459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1000802/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14647/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10160/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192053-1/
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

SUSE OpenStack Cloud 8:zypper in -t patch
SUSE-OpenStack-Cloud-8-2019-2053=1

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2019-2053=1

SUSE Linux Enterprise Software Development Kit 12-SP5:zypper in -t
patch SUSE-SLE-SDK-12-SP5-2019-2053=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-2053=1

SUSE Linux Enterprise Server for SAP 12-SP3:zypper in -t patch
SUSE-SLE-SAP-12-SP3-2019-2053=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2019-2053=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2019-2053=1

SUSE Linux Enterprise Server 12-SP5:zypper in -t patch
SUSE-SLE-SERVER-12-SP5-2019-2053=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-2053=1

SUSE Linux Enterprise Server 12-SP3-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2019-2053=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2019-2053=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2019-2053=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2019-2053=1

SUSE Linux Enterprise Module for Web Scripting 12:zypper in -t patch
SUSE-SLE-Module-Web-Scripting-12-2019-2053=1

SUSE Linux Enterprise Desktop 12-SP5:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP5-2019-2053=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-2053=1

SUSE Enterprise Storage 5:zypper in -t patch
SUSE-Storage-5-2019-2053=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2019-2053=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython3_4m1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython3_4m1_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-curses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
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
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0|1|2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1/2/3/4/5", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpython3_4m1_0-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpython3_4m1_0-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python3-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python3-base-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python3-base-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python3-base-debugsource-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python3-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python3-debugsource-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libpython3_4m1_0-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libpython3_4m1_0-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python3-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python3-base-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python3-base-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python3-base-debugsource-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python3-curses-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python3-curses-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python3-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python3-debugsource-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpython3_4m1_0-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpython3_4m1_0-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"python3-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"python3-base-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"python3-base-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"python3-base-debugsource-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"python3-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"python3-debugsource-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpython3_4m1_0-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpython3_4m1_0-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python3-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python3-base-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python3-base-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python3-base-debugsource-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python3-curses-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python3-curses-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python3-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python3-debugsource-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libpython3_4m1_0-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libpython3_4m1_0-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"python3-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"python3-base-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"python3-base-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"python3-base-debugsource-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"python3-curses-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"python3-curses-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"python3-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"python3-debugsource-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libpython3_4m1_0-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libpython3_4m1_0-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python3-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python3-base-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python3-base-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python3-base-debugsource-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python3-curses-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python3-curses-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python3-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python3-debugsource-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libpython3_4m1_0-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libpython3_4m1_0-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python3-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python3-base-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python3-base-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python3-base-debugsource-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python3-curses-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python3-curses-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python3-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python3-debugsource-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python3-tk-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python3-tk-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libpython3_4m1_0-32bit-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libpython3_4m1_0-debuginfo-32bit-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python3-base-debuginfo-32bit-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libpython3_4m1_0-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libpython3_4m1_0-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python3-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python3-base-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python3-base-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python3-base-debugsource-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python3-curses-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python3-curses-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python3-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python3-debugsource-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libpython3_4m1_0-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libpython3_4m1_0-32bit-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libpython3_4m1_0-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"libpython3_4m1_0-debuginfo-32bit-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"python3-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"python3-base-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"python3-base-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"python3-base-debuginfo-32bit-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"python3-base-debugsource-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"python3-curses-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"python3-curses-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"python3-debuginfo-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"python3-debugsource-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"python3-tk-3.4.6-25.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"python3-tk-debuginfo-3.4.6-25.29.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3");
}
