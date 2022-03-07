#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1877-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(126812);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/19 11:44:32");

  script_cve_id("CVE-2009-5155", "CVE-2019-9169");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : glibc (SUSE-SU-2019:1877-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for glibc fixes the following issues :

Security issues fixed :

CVE-2019-9169: Fixed a heap-based buffer over-read via an attempted
case-insensitive regular-expression match (bsc#1127308).

CVE-2009-5155: Fixed a denial of service in parse_reg_exp()
(bsc#1127223).

Non-security issues fixed: Does no longer compress debug sections in
crt*.o files (bsc#1123710)

Fixes a concurrency problem in ldconfig (bsc#1117993)

Fixes a race condition in pthread_mutex_lock while promoting to
PTHREAD_MUTEX_ELISION_NP (bsc#1131330)

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1117993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1123710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1127223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1127308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1131330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2009-5155/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9169/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191877-1/
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
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-1877=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-1877=1

SUSE Linux Enterprise Module for Development Tools 15-SP1:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-SP1-2019-1877=1

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2019-1877=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-1877=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-1877=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale-base-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-utils-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-utils-src-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nscd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/19");
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
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-32bit-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-devel-static-32bit-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-locale-base-32bit-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-locale-base-32bit-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-profile-32bit-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-utils-32bit-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-utils-32bit-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-utils-src-debugsource-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-32bit-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-devel-32bit-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-devel-32bit-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-32bit-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-32bit-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-debugsource-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-debugsource-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-devel-static-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-utils-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-utils-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-utils-src-debugsource-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-debugsource-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-devel-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-devel-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-extra-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-extra-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-locale-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-locale-base-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-locale-base-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-profile-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nscd-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nscd-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"glibc-32bit-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"glibc-devel-32bit-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"glibc-devel-32bit-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"glibc-32bit-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"glibc-32bit-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-debugsource-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-devel-static-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-utils-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-utils-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-utils-src-debugsource-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-debugsource-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-devel-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-devel-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-extra-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-extra-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-locale-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-locale-base-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-locale-base-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"glibc-profile-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nscd-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nscd-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"glibc-32bit-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"glibc-devel-static-32bit-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"glibc-locale-base-32bit-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"glibc-locale-base-32bit-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"glibc-profile-32bit-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"glibc-utils-32bit-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"glibc-utils-32bit-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"glibc-utils-src-debugsource-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"glibc-32bit-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"glibc-devel-32bit-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"glibc-devel-32bit-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"glibc-32bit-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"glibc-32bit-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"glibc-debugsource-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"glibc-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"glibc-debugsource-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"glibc-devel-static-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"glibc-utils-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"glibc-utils-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"glibc-utils-src-debugsource-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"glibc-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"glibc-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"glibc-debugsource-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"glibc-devel-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"glibc-devel-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"glibc-extra-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"glibc-extra-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"glibc-locale-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"glibc-locale-base-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"glibc-locale-base-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"glibc-profile-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"nscd-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"nscd-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"glibc-32bit-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"glibc-devel-32bit-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"glibc-devel-32bit-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"glibc-32bit-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"glibc-32bit-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-debugsource-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-devel-static-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-utils-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-utils-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-utils-src-debugsource-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-debugsource-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-devel-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-devel-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-extra-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-extra-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-locale-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-locale-base-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-locale-base-debuginfo-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"glibc-profile-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nscd-2.26-13.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nscd-debuginfo-2.26-13.24.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
