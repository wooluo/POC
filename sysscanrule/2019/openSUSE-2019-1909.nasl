#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1909.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(128001);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/22 16:57:38");

  script_cve_id("CVE-2018-19857", "CVE-2019-12874", "CVE-2019-13602", "CVE-2019-13962", "CVE-2019-5439", "CVE-2019-5459", "CVE-2019-5460");
  script_xref(name:"IAVB", value:"2019-B-0074");

  script_name(english:"openSUSE Security Update : vlc (openSUSE-2019-1909)");
  script_summary(english:"Check for the openSUSE-2019-1909 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for vlc to version 3.0.7.1 fixes the following issues :

Security issues fixed :

  - CVE-2019-5439: Fixed a buffer overflow (bsc#1138354).

  - CVE-2019-5459: Fixed an integer underflow (bsc#1143549).

  - CVE-2019-5460: Fixed a double free (bsc#1143547).

  - CVE-2019-12874: Fixed a double free in
    zlib_decompress_extra in modules/demux/mkv/util.cpp
    (bsc#1138933).

  - CVE-2019-13602: Fixed an integer underflow in mp4
    demuxer (boo#1141522).

  - CVE-2019-13962: Fixed a heap-based buffer over-read in
    avcodec (boo#1142161).

Non-security issues fixed :

  - Video Output :

  - Fix hardware acceleration with some AMD drivers

  - Improve direct3d11 HDR support

  - Access :

  - Improve Blu-ray support

  - Audio output :

  - Fix pass-through on Android-23

  - Fix DirectSound drain

  - Demux: Improve MP4 support

  - Video Output :

  - Fix 12 bits sources playback with Direct3D11

  - Fix crash on iOS

  - Fix midstream aspect-ratio changes when Windows hardware
    decoding is on

  - Fix HLG display with Direct3D11

  - Stream Output: Improve Chromecast support with new
    ChromeCast apps

  - Misc :

  - Update Youtube, Dailymotion, Vimeo, Soundcloud scripts

  - Work around busy looping when playing an invalid item
    with loop enabled

  - Updated translations.

New package libaom :

  - Initial version 1.0.0

  - A library for AOMedia Video 1 (AV1), an open,
    royalty-free video coding format designed for video
    transmissions over the Internet."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143549"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected vlc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:aom-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:aom-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaom-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaom-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaom0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaom0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlc5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlc5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlccore9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlccore9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-codec-gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-codec-gstreamer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-jack-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-noX");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-noX-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-vdpau");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-vdpau-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"aom-tools-1.0.0-lp150.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"aom-tools-debuginfo-1.0.0-lp150.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libaom-debugsource-1.0.0-lp150.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libaom-devel-1.0.0-lp150.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libaom0-1.0.0-lp150.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libaom0-debuginfo-1.0.0-lp150.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libvlc5-3.0.7.1-lp150.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libvlc5-debuginfo-3.0.7.1-lp150.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libvlccore9-3.0.7.1-lp150.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libvlccore9-debuginfo-3.0.7.1-lp150.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vlc-3.0.7.1-lp150.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vlc-codec-gstreamer-3.0.7.1-lp150.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vlc-codec-gstreamer-debuginfo-3.0.7.1-lp150.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vlc-debuginfo-3.0.7.1-lp150.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vlc-debugsource-3.0.7.1-lp150.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vlc-devel-3.0.7.1-lp150.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vlc-jack-3.0.7.1-lp150.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vlc-jack-debuginfo-3.0.7.1-lp150.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vlc-lang-3.0.7.1-lp150.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vlc-noX-3.0.7.1-lp150.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vlc-noX-debuginfo-3.0.7.1-lp150.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vlc-qt-3.0.7.1-lp150.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vlc-qt-debuginfo-3.0.7.1-lp150.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vlc-vdpau-3.0.7.1-lp150.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vlc-vdpau-debuginfo-3.0.7.1-lp150.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "aom-tools / aom-tools-debuginfo / libaom-debugsource / libaom-devel / etc");
}
