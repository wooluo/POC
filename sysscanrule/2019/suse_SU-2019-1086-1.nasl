#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1086-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(124403);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/30  9:38:18");

  script_cve_id("CVE-2019-11234", "CVE-2019-11235");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : freeradius-server (SUSE-SU-2019:1086-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for freeradius-server fixes the following issues :

Security issues fixed :

CVE-2019-11235: Fixed an authentication bypass related to the EAP-PWD
Commit frame and insufficent validation of elliptic curve points
(bsc#1132549).

CVE-2019-11234: Fixed an authentication bypass caused by reflecting
privous values back to the server (bsc#1132664).

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1132549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1132664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11234/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11235/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191086-1/
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
patch SUSE-SLE-Module-Server-Applications-15-2019-1086=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-1086=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/30");
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
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-debuginfo-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-debugsource-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-devel-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-krb5-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-krb5-debuginfo-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-ldap-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-ldap-debuginfo-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-libs-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-libs-debuginfo-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-mysql-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-mysql-debuginfo-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-perl-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-perl-debuginfo-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-postgresql-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-postgresql-debuginfo-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-python-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-python-debuginfo-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-sqlite-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-sqlite-debuginfo-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-utils-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-utils-debuginfo-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-debuginfo-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-debugsource-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freeradius-server-doc-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"freeradius-server-debuginfo-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"freeradius-server-debugsource-3.0.16-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"freeradius-server-doc-3.0.16-3.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius-server");
}