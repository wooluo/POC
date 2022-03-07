#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2106-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(127790);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-12974", "CVE-2019-12975", "CVE-2019-12976", "CVE-2019-12977", "CVE-2019-12978", "CVE-2019-12979", "CVE-2019-13133", "CVE-2019-13134", "CVE-2019-13135", "CVE-2019-13136", "CVE-2019-13137", "CVE-2019-13295", "CVE-2019-13296", "CVE-2019-13297", "CVE-2019-13298", "CVE-2019-13299", "CVE-2019-13300", "CVE-2019-13301", "CVE-2019-13302", "CVE-2019-13303", "CVE-2019-13304", "CVE-2019-13305", "CVE-2019-13306", "CVE-2019-13307", "CVE-2019-13308", "CVE-2019-13309", "CVE-2019-13310", "CVE-2019-13311", "CVE-2019-13391", "CVE-2019-13454");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ImageMagick (SUSE-SU-2019:2106-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes the following issues :

CVE-2019-13301: Fixed a memory leak in AcquireMagickMemory()
(bsc#1140554).

CVE-2019-13309: Fixed a memory leak at AcquireMagickMemory due to
mishandling the NoSuchImage error in CLIListOperatorImages
(bsc#1140520).

CVE-2019-13310: Fixed a memory leak at AcquireMagickMemory because of
an error in MagickWand/mogrify.c (bsc#1140501).

CVE-2019-13311: Fixed a memory leak at AcquireMagickMemory because of
a wand/mogrify.c error (bsc#1140513).

CVE-2019-13303: Fixed a heap-based buffer over-read in
MagickCore/composite.c in CompositeImage (bsc#1140549).

CVE-2019-13296: Fixed a memory leak in AcquireMagickMemory because of
an error in CLIListOperatorImages in MagickWand/operation.c
(bsc#1140665).

CVE-2019-13299: Fixed a heap-based buffer over-read at
MagickCore/pixel-accessor.h in GetPixelChannel (bsc#1140668).

CVE-2019-13454: Fixed a division by zero in RemoveDuplicateLayers in
MagickCore/layer.c (bsc#1141171).

CVE-2019-13295: Fixed a heap-based buffer over-read at
MagickCore/threshold.c in AdaptiveThresholdImage (bsc#1140664).

CVE-2019-13297: Fixed a heap-based buffer over-read at
MagickCore/threshold.c in AdaptiveThresholdImage (bsc#1140666).

CVE-2019-12979: Fixed the use of uninitialized values in
SyncImageSettings() (bsc#1139886).

CVE-2019-13391: Fixed a heap-based buffer over-read in
MagickCore/fourier.c (bsc#1140673).

CVE-2019-13308: Fixed a heap-based buffer overflow in
MagickCore/fourier.c (bsc#1140534).

CVE-2019-13302: Fixed a heap-based buffer over-read in
MagickCore/fourier.c in ComplexImages (bsc#1140552).

CVE-2019-13298: Fixed a heap-based buffer overflow at
MagickCore/pixel-accessor.h in SetPixelViaPixelInfo (bsc#1140667).

CVE-2019-13300: Fixed a heap-based buffer overflow at
MagickCore/statistic.c in EvaluateImages (bsc#1140669).

CVE-2019-13307: Fixed a heap-based buffer overflow at
MagickCore/statistic.c (bsc#1140538).

CVE-2019-12977: Fixed the use of uninitialized values in
WriteJP2Imag() (bsc#1139884).

CVE-2019-12975: Fixed a memory leak in the WriteDPXImage() in
coders/dpx.c (bsc#1140106).

CVE-2019-13135: Fixed the use of uninitialized values in
ReadCUTImage() (bsc#1140103).

CVE-2019-12978: Fixed the use of uninitialized values in
ReadPANGOImage() (bsc#1139885).

CVE-2019-12974: Fixed a NULL pointer dereference in the
ReadPANGOImage() (bsc#1140111).

CVE-2019-13304: Fixed a stack-based buffer overflow at coders/pnm.c in
WritePNMImage (bsc#1140547).

CVE-2019-13305: Fixed one more stack-based buffer overflow at
coders/pnm.c in WritePNMImage (bsc#1140545).

CVE-2019-13306: Fixed an additional stack-based buffer overflow at
coders/pnm.c in WritePNMImage (bsc#1140543).

CVE-2019-13133: Fixed a memory leak in the ReadBMPImage()
(bsc#1140100).

CVE-2019-13134: Fixed a memory leak in the ReadVIFFImage()
(bsc#1140102).

CVE-2019-13137: Fixed a memory leak in the ReadPSImage()
(bsc#1140105).

CVE-2019-13136: Fixed a integer overflow vulnerability in the
TIFFSeekCustomStream() (bsc#1140104).

CVE-2019-12976: Fixed a memory leak in the ReadPCLImage() in
coders/pcl.c(bsc#1140110).

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1139884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1139885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1139886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1141171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12974/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12975/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12976/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12977/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12978/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12979/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13133/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13134/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13135/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13136/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13137/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13295/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13296/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13297/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13298/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13299/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13300/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13301/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13302/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13303/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13304/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13305/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13306/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13307/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13308/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13309/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13310/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13311/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13391/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13454/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192106-1/
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
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-2106=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-2106=1

SUSE Linux Enterprise Module for Development Tools 15-SP1:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-SP1-2019-2106=1

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2019-2106=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Desktop-Applications-15-SP1-2019-2106=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2019-2106=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/09");
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
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"ImageMagick-devel-32bit-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libMagick++-7_Q16HDRI4-32bit-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libMagick++-7_Q16HDRI4-32bit-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libMagick++-devel-32bit-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libMagickCore-7_Q16HDRI6-32bit-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libMagickCore-7_Q16HDRI6-32bit-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libMagickWand-7_Q16HDRI6-32bit-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libMagickWand-7_Q16HDRI6-32bit-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-config-7-upstream-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-debugsource-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-extra-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-extra-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-debugsource-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"perl-PerlMagick-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"perl-PerlMagick-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-config-7-SUSE-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-debugsource-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-devel-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagick++-7_Q16HDRI4-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagick++-7_Q16HDRI4-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagick++-devel-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagickCore-7_Q16HDRI6-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagickCore-7_Q16HDRI6-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagickWand-7_Q16HDRI6-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagickWand-7_Q16HDRI6-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-debugsource-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-extra-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-extra-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-debugsource-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"perl-PerlMagick-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"perl-PerlMagick-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-config-7-SUSE-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-config-7-upstream-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-debugsource-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-devel-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagick++-7_Q16HDRI4-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagick++-7_Q16HDRI4-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagick++-devel-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagickCore-7_Q16HDRI6-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagickCore-7_Q16HDRI6-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagickWand-7_Q16HDRI6-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagickWand-7_Q16HDRI6-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"ImageMagick-devel-32bit-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libMagick++-7_Q16HDRI4-32bit-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libMagick++-7_Q16HDRI4-32bit-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libMagick++-devel-32bit-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libMagickCore-7_Q16HDRI6-32bit-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libMagickCore-7_Q16HDRI6-32bit-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libMagickWand-7_Q16HDRI6-32bit-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libMagickWand-7_Q16HDRI6-32bit-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-config-7-upstream-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-debugsource-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-extra-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-extra-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-debugsource-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"perl-PerlMagick-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"perl-PerlMagick-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-config-7-SUSE-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-debugsource-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-devel-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagick++-7_Q16HDRI4-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagick++-7_Q16HDRI4-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagick++-devel-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagickCore-7_Q16HDRI6-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagickCore-7_Q16HDRI6-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagickWand-7_Q16HDRI6-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagickWand-7_Q16HDRI6-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-debugsource-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-extra-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-extra-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-debugsource-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"perl-PerlMagick-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"perl-PerlMagick-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-config-7-SUSE-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-config-7-upstream-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-debugsource-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-devel-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagick++-7_Q16HDRI4-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagick++-7_Q16HDRI4-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagick++-devel-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagickCore-7_Q16HDRI6-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagickCore-7_Q16HDRI6-debuginfo-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagickWand-7_Q16HDRI6-7.0.7.34-3.67.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagickWand-7_Q16HDRI6-debuginfo-7.0.7.34-3.67.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick");
}
