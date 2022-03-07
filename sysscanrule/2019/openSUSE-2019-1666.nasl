#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1666.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126368);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/03 12:01:42");

  script_cve_id("CVE-2019-5787", "CVE-2019-5788", "CVE-2019-5789", "CVE-2019-5790", "CVE-2019-5791", "CVE-2019-5792", "CVE-2019-5793", "CVE-2019-5794", "CVE-2019-5795", "CVE-2019-5796", "CVE-2019-5797", "CVE-2019-5798", "CVE-2019-5799", "CVE-2019-5800", "CVE-2019-5801", "CVE-2019-5802", "CVE-2019-5803", "CVE-2019-5804", "CVE-2019-5805", "CVE-2019-5806", "CVE-2019-5807", "CVE-2019-5808", "CVE-2019-5809", "CVE-2019-5810", "CVE-2019-5811", "CVE-2019-5812", "CVE-2019-5813", "CVE-2019-5814", "CVE-2019-5815", "CVE-2019-5816", "CVE-2019-5817", "CVE-2019-5818", "CVE-2019-5819", "CVE-2019-5820", "CVE-2019-5821", "CVE-2019-5822", "CVE-2019-5823", "CVE-2019-5824", "CVE-2019-5827", "CVE-2019-5828", "CVE-2019-5829", "CVE-2019-5830", "CVE-2019-5831", "CVE-2019-5832", "CVE-2019-5833", "CVE-2019-5834", "CVE-2019-5835", "CVE-2019-5836", "CVE-2019-5837", "CVE-2019-5838", "CVE-2019-5839", "CVE-2019-5840", "CVE-2019-5842");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2019-1666)");
  script_summary(english:"Check for the openSUSE-2019-1666 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for chromium fixes the following issues :

Chromium was updated to 75.0.3770.90 (boo#1137332 boo#1138287) :

  - CVE-2019-5842: Use-after-free in Blink.

Also updated to 75.0.3770.80 boo#1137332 :

  - CVE-2019-5828: Use after free in ServiceWorker

  - CVE-2019-5829: Use after free in Download Manager

  - CVE-2019-5830: Incorrectly credentialed requests in CORS

  - CVE-2019-5831: Incorrect map processing in V8

  - CVE-2019-5832: Incorrect CORS handling in XHR

  - CVE-2019-5833: Inconsistent security UI placemen

  - CVE-2019-5835: Out of bounds read in Swiftshader

  - CVE-2019-5836: Heap buffer overflow in Angle

  - CVE-2019-5837: Cross-origin resources size disclosure in
    Appcache

  - CVE-2019-5838: Overly permissive tab access in
    Extensions

  - CVE-2019-5839: Incorrect handling of certain code points
    in Blink

  - CVE-2019-5840: Popup blocker bypass

  - Various fixes from internal audits, fuzzing and other
    initiatives

  - CVE-2019-5834: URL spoof in Omnibox on iOS

Update to 74.0.3729.169 :

  - Feature fixes update only

Update to 74.0.3729.157 :

  - Various security fixes from internal audits, fuzzing and
    other initiatives

Includes security fixes from 74.0.3729.131 (boo#1134218) :

  - CVE-2019-5827: Out-of-bounds access in SQLite

  - CVE-2019-5824: Parameter passing error in media player

Update to 74.0.3729.108 boo#1133313 :

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

  - CVE-2019-5812: URL spoof in Omnibox on iOS

  - CVE-2019-5816: Exploit persistence extension on Android

  - CVE-2019-5817: Heap buffer overflow in Angle on Windows

Update to 73.0.3686.103 :

  - Various feature fixes

Update to 73.0.3683.86 :

  - Just feature fixes around

  - Update conditions to use system harfbuzz on TW+

  - Require java during build

  - Enable using pipewire when available

  - Rebase chromium-vaapi.patch to match up the Fedora one

Update to 73.0.3683.75 boo#1129059 :

  - CVE-2019-5787: Use after free in Canvas.

  - CVE-2019-5788: Use after free in FileAPI.

  - CVE-2019-5789: Use after free in WebMIDI.

  - CVE-2019-5790: Heap buffer overflow in V8.

  - CVE-2019-5791: Type confusion in V8.

  - CVE-2019-5792: Integer overflow in PDFium.

  - CVE-2019-5793: Excessive permissions for private API in
    Extensions.

  - CVE-2019-5794: Security UI spoofing.

  - CVE-2019-5795: Integer overflow in PDFium.

  - CVE-2019-5796: Race condition in Extensions.

  - CVE-2019-5797: Race condition in DOMStorage.

  - CVE-2019-5798: Out of bounds read in Skia.

  - CVE-2019-5799: CSP bypass with blob URL.

  - CVE-2019-5800: CSP bypass with blob URL.

  - CVE-2019-5801: Incorrect Omnibox display on iOS.

  - CVE-2019-5802: Security UI spoofing.

  - CVE-2019-5803: CSP bypass with JavaScript URLs'.

  - CVE-2019-5804: Command line command injection on
    Windows."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138287"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/01");
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
if (release !~ "^(SUSE15\.0|SUSE15\.1|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 15.1 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"chromedriver-75.0.3770.90-lp150.218.4") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromedriver-debuginfo-75.0.3770.90-lp150.218.4") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-75.0.3770.90-lp150.218.4") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-debuginfo-75.0.3770.90-lp150.218.4") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-debugsource-75.0.3770.90-lp150.218.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-75.0.3770.90-lp151.2.9.3") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-debuginfo-75.0.3770.90-lp151.2.9.3") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-75.0.3770.90-lp151.2.9.3") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-debuginfo-75.0.3770.90-lp151.2.9.3") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-debugsource-75.0.3770.90-lp151.2.9.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-75.0.3770.90-217.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromedriver-debuginfo-75.0.3770.90-217.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-75.0.3770.90-217.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debuginfo-75.0.3770.90-217.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"chromium-debugsource-75.0.3770.90-217.1") ) flag++;

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
