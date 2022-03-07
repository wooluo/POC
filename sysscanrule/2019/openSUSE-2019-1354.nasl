#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1354.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(124754);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/10 10:59:32");

  script_cve_id("CVE-2019-11008", "CVE-2019-11009", "CVE-2019-11473", "CVE-2019-11474", "CVE-2019-11505", "CVE-2019-11506");

  script_name(english:"openSUSE Security Update : GraphicsMagick (openSUSE-2019-1354)");
  script_summary(english:"Check for the openSUSE-2019-1354 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for GraphicsMagick fixes the following issues :

Security issues fixed :

  - CVE-2019-11506: Fixed a heap-based buffer overflow in
    the function WriteMATLABImage (boo#1133498).

  - CVE-2019-11505: Fixed a heap-based buffer overflow in
    the function WritePDBImage (boo#1133501).

The following fixes where modified and refreshed :

  - CVE-2019-11008: Fixed a heap-based buffer overflow in
    the function WriteXWDImage (boo#1132054).

  - CVE-2019-11009: Fixed a heap-based buffer over-read in
    the function ReadXWDImage (boo#1132053).

  - CVE-2019-11473: Fixed an out-of-bounds read leading to a
    possible denial of service in coders/xwd.c
    (boo#1133203).

  - CVE-2019-11474: Fixed a floating-point exception leading
    to a possible denial of service in coders/xwd.c
    (boo#1133202)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133501"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected GraphicsMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-Q16-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-Q16-12-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick-Q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick-Q16-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick3-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagickWand-Q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagickWand-Q16-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-GraphicsMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/10");
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

if ( rpm_check(release:"SUSE15.0", reference:"GraphicsMagick-1.3.29-lp150.3.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"GraphicsMagick-debuginfo-1.3.29-lp150.3.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"GraphicsMagick-debugsource-1.3.29-lp150.3.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"GraphicsMagick-devel-1.3.29-lp150.3.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libGraphicsMagick++-Q16-12-1.3.29-lp150.3.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libGraphicsMagick++-Q16-12-debuginfo-1.3.29-lp150.3.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libGraphicsMagick++-devel-1.3.29-lp150.3.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libGraphicsMagick-Q16-3-1.3.29-lp150.3.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libGraphicsMagick-Q16-3-debuginfo-1.3.29-lp150.3.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libGraphicsMagick3-config-1.3.29-lp150.3.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libGraphicsMagickWand-Q16-2-1.3.29-lp150.3.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libGraphicsMagickWand-Q16-2-debuginfo-1.3.29-lp150.3.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"perl-GraphicsMagick-1.3.29-lp150.3.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"perl-GraphicsMagick-debuginfo-1.3.29-lp150.3.28.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GraphicsMagick / GraphicsMagick-debuginfo / etc");
}
