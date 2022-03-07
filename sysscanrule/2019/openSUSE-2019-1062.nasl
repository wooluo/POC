#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1062.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(123492);
  script_version("1.4");
  script_cvs_date("Date: 2019/05/29 10:47:07");

  script_cve_id("CVE-2019-5787", "CVE-2019-5788", "CVE-2019-5789", "CVE-2019-5790", "CVE-2019-5791", "CVE-2019-5792", "CVE-2019-5793", "CVE-2019-5794", "CVE-2019-5795", "CVE-2019-5796", "CVE-2019-5797", "CVE-2019-5798", "CVE-2019-5799", "CVE-2019-5800", "CVE-2019-5801", "CVE-2019-5802", "CVE-2019-5803", "CVE-2019-5804");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2019-1062)");
  script_summary(english:"Check for the openSUSE-2019-1062 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for chromium to version 73.0.3683.75 fixes the following
issues :

Security issues fixed (bsc#1129059) :

  - CVE-2019-5787: Fixed a use after free in Canvas.

  - CVE-2019-5788: Fixed a use after free in FileAPI.

  - CVE-2019-5789: Fixed a use after free in WebMIDI.

  - CVE-2019-5790: Fixed a heap buffer overflow in V8.

  - CVE-2019-5791: Fixed a type confusion in V8.

  - CVE-2019-5792: Fixed an integer overflow in PDFium.

  - CVE-2019-5793: Fixed excessive permissions for private
    API in Extensions.

  - CVE-2019-5794: Fixed security UI spoofing.

  - CVE-2019-5795: Fixed an integer overflow in PDFium.

  - CVE-2019-5796: Fixed a race condition in Extensions.

  - CVE-2019-5797: Fixed a race condition in DOMStorage.

  - CVE-2019-5798: Fixed an out of bounds read in Skia.

  - CVE-2019-5799: Fixed a CSP bypass with blob URL.

  - CVE-2019-5800: Fixed a CSP bypass with blob URL.

  - CVE-2019-5801: Fixed an incorrect Omnibox display on
    iOS.

  - CVE-2019-5802: Fixed security UI spoofing.

  - CVE-2019-5803: Fixed a CSP bypass with JavaScript URLs'.

  - CVE-2019-5804: Fixed a command line injection on
    Windows.

Release notes:
https://chromereleases.googleblog.com/2019/03/stable-channel-update-fo
r-desktop_12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129059"
  );
  # https://chromereleases.googleblog.com/2019/03/stable-channel-update-for-desktop_12.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/29");
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

if ( rpm_check(release:"SUSE15.0", reference:"chromedriver-73.0.3683.75-lp150.206.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromedriver-debuginfo-73.0.3683.75-lp150.206.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-73.0.3683.75-lp150.206.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-debuginfo-73.0.3683.75-lp150.206.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-debugsource-73.0.3683.75-lp150.206.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
