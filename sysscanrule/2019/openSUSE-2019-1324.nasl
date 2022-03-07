#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1324.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(124640);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/01 11:41:24");

  script_cve_id("CVE-2019-5805", "CVE-2019-5806", "CVE-2019-5807", "CVE-2019-5808", "CVE-2019-5809", "CVE-2019-5810", "CVE-2019-5811", "CVE-2019-5813", "CVE-2019-5814", "CVE-2019-5815", "CVE-2019-5818", "CVE-2019-5819", "CVE-2019-5820", "CVE-2019-5821", "CVE-2019-5822", "CVE-2019-5823");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2019-1324)");
  script_summary(english:"Check for the openSUSE-2019-1324 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for chromium fixes the following issues :

Security update to version 74.0.3729.108 (boo#1133313).

Security issues fixed :

  - CVE-2019-5805: Use after free in PDFium

  - CVE-2019-5806: Integer overflow in Angle

  - CVE-2019-5807: Memory corruption in V8

  - CVE-2019-5808: Use after free in Blink

  - CVE-2019-5809: Use after free in Blink

  - CVE-2019-5810: User information disclosure in Autofill

  - CVE-2019-5811: CORS bypass in Blink

  - CVE-2019-5813: Out of bounds read in V8

  - CVE-2019-5814: CORS bypass in Blink

  - CVE-2019-5815: Heap buffer overflow in Blink

  - CVE-2019-5818: Uninitialized value in media reader

  - CVE-2019-5819: Incorrect escaping in developer tools

  - CVE-2019-5820: Integer overflow in PDFium

  - CVE-2019-5821: Integer overflow in PDFium

  - CVE-2019-5822: CORS bypass in download manager

  - CVE-2019-5823: Forced navigation from service worker

Bug fixes :

  - Update to 73.0.3686.103 :

  - Various feature fixes

  - Update to 73.0.3683.86 :

  - Various feature fixes

  - Update conditions to use system harfbuzz on TW+

  - Require java during build

  - Enable using pipewire when available

  - Rebase chromium-vaapi.patch to match up the Fedora one"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133313"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/06");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-74.0.3729.108-208.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-debuginfo-74.0.3729.108-208.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-74.0.3729.108-208.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debuginfo-74.0.3729.108-208.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debugsource-74.0.3729.108-208.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
