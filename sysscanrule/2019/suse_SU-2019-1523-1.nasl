#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1523-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(125987);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/18 10:31:31");

  script_cve_id("CVE-2019-11470", "CVE-2019-11472", "CVE-2019-11505", "CVE-2019-11506", "CVE-2019-11598");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ImageMagick (SUSE-SU-2019:1523-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes the following issues :

Security issues fixed :

CVE-2019-11472: Fixed a denial-of-service in ReadXWDImage()
(bsc#1133204).

CVE-2019-11470: Fixed a denial-of-service in ReadCINImage()
(bsc#1133205).

CVE-2019-11506: Fixed a heap-based buffer overflow in the
WriteMATLABImage() (bsc#1133498).

CVE-2019-11505: Fixed a heap-based buffer overflow in the
WritePDBImage() (bsc#1133501).

CVE-2019-11598: Fixed a heap-based buffer overread in WritePNMImage()
(bsc#1136732)

We also now disable PCL in the -SUSE configuration, as it also uses
ghostscript for decoding (bsc#1136183)

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1133204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1133205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1133498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1133501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1136183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1136732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11470/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11472/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11505/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11506/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11598/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191523-1/
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
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-1523=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-1523=1

SUSE Linux Enterprise Module for Development Tools 15-SP1:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-SP1-2019-1523=1

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2019-1523=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Desktop-Applications-15-SP1-2019-1523=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2019-1523=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-config-7-SUSE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-config-7-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagick++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagick++-7_Q16HDRI4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagick++-7_Q16HDRI4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagick++-7_Q16HDRI4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore-7_Q16HDRI6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore-7_Q16HDRI6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore-7_Q16HDRI6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickWand");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickWand-7_Q16HDRI6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickWand-7_Q16HDRI6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickWand-7_Q16HDRI6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PerlMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PerlMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/18");
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
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"ImageMagick-devel-32bit-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libMagick++-7_Q16HDRI4-32bit-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libMagick++-7_Q16HDRI4-32bit-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libMagick++-devel-32bit-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libMagickCore-7_Q16HDRI6-32bit-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libMagickCore-7_Q16HDRI6-32bit-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libMagickWand-7_Q16HDRI6-32bit-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libMagickWand-7_Q16HDRI6-32bit-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-config-7-upstream-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-debugsource-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-extra-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-extra-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-debugsource-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"perl-PerlMagick-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"perl-PerlMagick-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-config-7-SUSE-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-debugsource-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-devel-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagick++-7_Q16HDRI4-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagick++-7_Q16HDRI4-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagick++-devel-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagickCore-7_Q16HDRI6-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagickCore-7_Q16HDRI6-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagickWand-7_Q16HDRI6-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagickWand-7_Q16HDRI6-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-debugsource-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-extra-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-extra-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-debugsource-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"perl-PerlMagick-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"perl-PerlMagick-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-config-7-SUSE-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-config-7-upstream-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-debugsource-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-devel-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagick++-7_Q16HDRI4-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagick++-7_Q16HDRI4-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagick++-devel-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagickCore-7_Q16HDRI6-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagickCore-7_Q16HDRI6-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagickWand-7_Q16HDRI6-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagickWand-7_Q16HDRI6-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"ImageMagick-devel-32bit-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libMagick++-7_Q16HDRI4-32bit-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libMagick++-7_Q16HDRI4-32bit-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libMagick++-devel-32bit-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libMagickCore-7_Q16HDRI6-32bit-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libMagickCore-7_Q16HDRI6-32bit-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libMagickWand-7_Q16HDRI6-32bit-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libMagickWand-7_Q16HDRI6-32bit-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-config-7-upstream-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-debugsource-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-extra-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-extra-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-debugsource-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"perl-PerlMagick-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"perl-PerlMagick-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-config-7-SUSE-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-debugsource-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-devel-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagick++-7_Q16HDRI4-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagick++-7_Q16HDRI4-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagick++-devel-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagickCore-7_Q16HDRI6-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagickCore-7_Q16HDRI6-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagickWand-7_Q16HDRI6-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagickWand-7_Q16HDRI6-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-debugsource-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-extra-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-extra-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-debugsource-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"perl-PerlMagick-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"perl-PerlMagick-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-config-7-SUSE-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-config-7-upstream-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-debugsource-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-devel-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagick++-7_Q16HDRI4-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagick++-7_Q16HDRI4-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagick++-devel-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagickCore-7_Q16HDRI6-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagickCore-7_Q16HDRI6-debuginfo-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagickWand-7_Q16HDRI6-7.0.7.34-3.61.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagickWand-7_Q16HDRI6-debuginfo-7.0.7.34-3.61.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick");
}
