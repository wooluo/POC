#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1810-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(126618);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/11 12:05:32");

  script_cve_id("CVE-2019-10130", "CVE-2019-10164");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : postgresql10 (SUSE-SU-2019:1810-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for postgresql10 fixes the following issues :

Security issue fixed :

CVE-2019-10164: Fixed buffer-overflow vulnerabilities in SCRAM
verifier parsing (bsc#1138034).

CVE-2019-10130: Prevent row-level security policies from being
bypassed via selectivity estimators (bsc#1134689).

Bug fixes: For a complete list of fixes check the release notes.

    - https://www.postgresql.org/docs/10/release-10-9.html

    - https://www.postgresql.org/docs/10/release-10-8.html

    - https://www.postgresql.org/docs/10/release-10-7.html

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1134689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1138034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/10/release-10-7.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/10/release-10-8.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/10/release-10-9.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10130/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-10164/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191810-1/
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
patch SUSE-SLE-Module-Server-Applications-15-2019-1810=1

SUSE Linux Enterprise Module for Packagehub Subpackages 15:zypper in
-t patch SUSE-SLE-Module-Packagehub-Subpackages-15-2019-1810=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-1810=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-1810=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/11");
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
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libpq5-32bit-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libpq5-32bit-debuginfo-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libecpg6-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libecpg6-debuginfo-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-contrib-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-contrib-debuginfo-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-debuginfo-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-debugsource-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-devel-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-devel-debuginfo-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-plperl-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-plperl-debuginfo-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-plpython-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-plpython-debuginfo-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-pltcl-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-pltcl-debuginfo-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-server-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-server-debuginfo-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-debuginfo-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-debugsource-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-test-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-debuginfo-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-debugsource-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-test-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpq5-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpq5-debuginfo-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-debuginfo-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"postgresql10-debugsource-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libpq5-32bit-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libpq5-32bit-debuginfo-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"postgresql10-debuginfo-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"postgresql10-debugsource-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"postgresql10-test-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"postgresql10-debuginfo-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"postgresql10-debugsource-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"postgresql10-test-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpq5-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpq5-debuginfo-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"postgresql10-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"postgresql10-debuginfo-10.9-4.13.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"postgresql10-debugsource-10.9-4.13.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql10");
}
