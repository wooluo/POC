#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1213.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(124106);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/17  9:22:56");

  script_cve_id("CVE-2019-7572", "CVE-2019-7573", "CVE-2019-7574", "CVE-2019-7575", "CVE-2019-7576", "CVE-2019-7577", "CVE-2019-7578", "CVE-2019-7635", "CVE-2019-7636", "CVE-2019-7637", "CVE-2019-7638");

  script_name(english:"openSUSE Security Update : SDL (openSUSE-2019-1213)");
  script_summary(english:"Check for the openSUSE-2019-1213 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for SDL fixes the following issues: &#9; Security issues
fixed:&#9; 

  - CVE-2019-7572: Fixed a buffer over-read in
    IMA_ADPCM_nibble in audio/SDL_wave.c.(bsc#1124806).

  - CVE-2019-7578: Fixed a heap-based buffer over-read in
    InitIMA_ADPCM in audio/SDL_wave.c (bsc#1125099).

  - CVE-2019-7576: Fixed heap-based buffer over-read in
    InitMS_ADPCM in audio/SDL_wave.c (bsc#1124799).

  - CVE-2019-7573: Fixed a heap-based buffer over-read in
    InitMS_ADPCM in audio/SDL_wave.c (bsc#1124805).

  - CVE-2019-7635: Fixed a heap-based buffer over-read in
    Blit1to4 in video/SDL_blit_1.c. (bsc#1124827).

  - CVE-2019-7636: Fixed a heap-based buffer over-read in
    SDL_GetRGB in video/SDL_pixels.c (bsc#1124826).

  - CVE-2019-7638: Fixed a heap-based buffer over-read in
    Map1toN in video/SDL_pixels.c (bsc#1124824).

  - CVE-2019-7574: Fixed a heap-based buffer over-read in
    IMA_ADPCM_decode in audio/SDL_wave.c (bsc#1124803).

  - CVE-2019-7575: Fixed a heap-based buffer overflow in
    MS_ADPCM_decode in audio/SDL_wave.c (bsc#1124802).

  - CVE-2019-7637: Fixed a heap-based buffer overflow in
    SDL_FillRect function in SDL_surface.c (bsc#1124825).

  - CVE-2019-7577: Fixed a buffer over read in
    SDL_LoadWAV_RW in audio/SDL_wave.c (bsc#1124800). 

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125099"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected SDL packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:SDL-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL-1_2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL-1_2-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL-1_2-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL-1_2-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"SDL-debugsource-1.2.15-20.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libSDL-1_2-0-1.2.15-20.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libSDL-1_2-0-debuginfo-1.2.15-20.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libSDL-devel-1.2.15-20.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libSDL-1_2-0-32bit-1.2.15-20.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libSDL-1_2-0-debuginfo-32bit-1.2.15-20.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libSDL-devel-32bit-1.2.15-20.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SDL-debugsource / libSDL-1_2-0 / libSDL-1_2-0-32bit / etc");
}
