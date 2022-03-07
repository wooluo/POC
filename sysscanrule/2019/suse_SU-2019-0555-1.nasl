#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0555-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(122664);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/07 17:16:14");

  script_cve_id("CVE-2016-9843", "CVE-2018-3058", "CVE-2018-3060", "CVE-2018-3063", "CVE-2018-3064", "CVE-2018-3066", "CVE-2018-3143", "CVE-2018-3156", "CVE-2018-3162", "CVE-2018-3173", "CVE-2018-3174", "CVE-2018-3185", "CVE-2018-3200", "CVE-2018-3251", "CVE-2018-3277", "CVE-2018-3282", "CVE-2018-3284", "CVE-2019-2510", "CVE-2019-2537");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : mariadb (SUSE-SU-2019:0555-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mariadb to version 10.2.22 fixes the following 
issues :

Security issues fixed :

CVE-2019-2510: Fixed a vulnerability which can lead to MySQL
compromise and lead to Denial of Service (bsc#1122198).

CVE-2019-2537: Fixed a vulnerability which can lead to MySQL
compromise and lead to Denial of Service (bsc#1122198).

CVE-2018-3284: Fixed InnoDB unspecified vulnerability (CPU Oct 2018)
(bsc#1112377)

CVE-2018-3282: Server Storage Engines unspecified vulnerability (CPU
Oct 2018) (bsc#1112432)

CVE-2018-3277: Fixed InnoDB unspecified vulnerability (CPU Oct 2018)
(bsc#1112391)

CVE-2018-3251: InnoDB unspecified vulnerability (CPU Oct 2018)
(bsc#1112397)

CVE-2018-3200: Fixed InnoDB unspecified vulnerability (CPU Oct 2018)
(bsc#1112404)

CVE-2018-3185: Fixed InnoDB unspecified vulnerability (CPU Oct 2018)
(bsc#1112384)

CVE-2018-3174: Client programs unspecified vulnerability (CPU Oct
2018) (bsc#1112368)

CVE-2018-3173: Fixed InnoDB unspecified vulnerability (CPU Oct 2018)
(bsc#1112386)

CVE-2018-3162: Fixed InnoDB unspecified vulnerability (CPU Oct 2018)
(bsc#1112415)

CVE-2018-3156: InnoDB unspecified vulnerability (CPU Oct 2018)
(bsc#1112417)

CVE-2018-3143: InnoDB unspecified vulnerability (CPU Oct 2018)
(bsc#1112421)

CVE-2018-3066: Unspecified vulnerability in the MySQL Server component
of Oracle MySQL (subcomponent Server Options). (bsc#1101678)

CVE-2018-3064: InnoDB unspecified vulnerability (CPU Jul 2018)
(bsc#1103342)

CVE-2018-3063: Unspecified vulnerability in the MySQL Server component
of Oracle MySQL (subcomponent Server Security Privileges).
(bsc#1101677)

CVE-2018-3058: Unspecified vulnerability in the MySQL Server component
of Oracle MySQL (subcomponent MyISAM). (bsc#1101676)

CVE-2016-9843: Big-endian out-of-bounds pointer (bsc#1013882)

Non-security issues fixed: Fixed an issue where mysl_install_db fails
due to incorrect basedir (bsc#1127027).

Fixed an issue where the lograte was not working (bsc#1112767).

Backport Information Schema CHECK_CONSTRAINTS Table.

Maximum value of table_definition_cache is now 2097152.

InnoDB ALTER TABLE fixes.

Galera crash recovery fixes.

Encryption fixes.

Remove xtrabackup dependency as MariaDB ships a build in mariabackup
so xtrabackup is not needed (bsc#1122475).

Maria DB testsuite - test main.plugin_auth failed (bsc#1111859)

Maria DB testsuite - test encryption.second_plugin-12863 failed
(bsc#1111858)

Remove PerconaFT from the package as it has AGPL licence (bsc#1118754)

remove PerconaFT from the package as it has AGPL licence (bsc#1118754)

Database corruption after renaming a prefix-indexed column
(bsc#1120041)

Release notes and changelog:
https://mariadb.com/kb/en/library/mariadb-10222-release-notes

https://mariadb.com/kb/en/library/mariadb-10222-changelog/

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1013882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1116686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1118754"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1120041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1122198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1122475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1127027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10222-changelog/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10222-release-notes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9843/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3058/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3060/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3063/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3064/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3066/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3143/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3156/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3162/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3173/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3174/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3185/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3200/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3251/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3277/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3282/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3284/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-2510/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-2537/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190555-1/
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

SUSE Linux Enterprise Module for Server Applications 15:zypper in -t
patch SUSE-SLE-Module-Server-Applications-15-2019-555=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-555=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqld-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqld19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqld19-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/07");
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
if (rpm_check(release:"SLES15", sp:"0", reference:"libmysqld-devel-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmysqld19-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmysqld19-debuginfo-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mariadb-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mariadb-client-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mariadb-client-debuginfo-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mariadb-debuginfo-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mariadb-debugsource-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mariadb-tools-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mariadb-tools-debuginfo-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mariadb-bench-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mariadb-bench-debuginfo-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mariadb-debuginfo-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mariadb-debugsource-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mariadb-galera-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mariadb-test-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"mariadb-test-debuginfo-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"mariadb-bench-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"mariadb-bench-debuginfo-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"mariadb-debuginfo-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"mariadb-debugsource-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"mariadb-galera-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"mariadb-test-10.2.22-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"mariadb-test-debuginfo-10.2.22-3.14.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb");
}
