#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0571-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(122715);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/08 10:15:34");

  script_cve_id("CVE-2018-10360", "CVE-2019-8905", "CVE-2019-8906", "CVE-2019-8907");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : file (SUSE-SU-2019:0571-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for file fixes the following issues :

The following security vulnerabilities were addressed :

CVE-2018-10360: Fixed an out-of-bounds read in the function
do_core_note in readelf.c, which allowed remote attackers to cause a
denial of service (application crash) via a crafted ELF file
(bsc#1096974)

CVE-2019-8905: Fixed a stack-based buffer over-read in do_core_note in
readelf.c (bsc#1126118)

CVE-2019-8906: Fixed an out-of-bounds read in do_core_note in readelf.
c (bsc#1126119)

CVE-2019-8907: Fixed a stack corruption in do_core_note in readelf.c
(bsc#1126117)

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1096974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1096984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10360/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8905/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8906/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8907/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190571-1/
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

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2019-571=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-571=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:file-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:file-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:file-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmagic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmagic1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmagic1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-magic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-magic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/08");
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
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libmagic1-32bit-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libmagic1-32bit-debuginfo-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-magic-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"file-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"file-debuginfo-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"file-debugsource-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"file-devel-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmagic1-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmagic1-debuginfo-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python2-magic-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libmagic1-32bit-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libmagic1-32bit-debuginfo-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-magic-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"file-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"file-debuginfo-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"file-debugsource-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"file-devel-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmagic1-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmagic1-debuginfo-5.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python2-magic-5.32-7.5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "file");
}
