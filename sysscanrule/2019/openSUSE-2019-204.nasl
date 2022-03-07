#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-204.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(122304);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/20  9:20:29");

  script_cve_id("CVE-2019-5754", "CVE-2019-5755", "CVE-2019-5756", "CVE-2019-5757", "CVE-2019-5758", "CVE-2019-5759", "CVE-2019-5760", "CVE-2019-5761", "CVE-2019-5762", "CVE-2019-5763", "CVE-2019-5764", "CVE-2019-5765", "CVE-2019-5766", "CVE-2019-5767", "CVE-2019-5768", "CVE-2019-5769", "CVE-2019-5770", "CVE-2019-5771", "CVE-2019-5772", "CVE-2019-5773", "CVE-2019-5774", "CVE-2019-5775", "CVE-2019-5776", "CVE-2019-5777", "CVE-2019-5778", "CVE-2019-5779", "CVE-2019-5780", "CVE-2019-5781", "CVE-2019-5782", "CVE-2019-5784");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2019-204)");
  script_summary(english:"Check for the openSUSE-2019-204 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for Chromium to version 72.0.3626.96 fixes the following
issues :

Security issues fixed (bsc#1123641 and bsc#1124936) :

  - CVE-2019-5784: Inappropriate implementation in V8 

  - CVE-2019-5754: Inappropriate implementation in QUIC
    Networking.

  - CVE-2019-5782: Inappropriate implementation in V8. 

  - CVE-2019-5755: Inappropriate implementation in V8. 

  - CVE-2019-5756: Use after free in PDFium. 

  - CVE-2019-5757: Type Confusion in SVG.

  - CVE-2019-5758: Use after free in Blink.

  - CVE-2019-5759: Use after free in HTML select elements.

  - CVE-2019-5760: Use after free in WebRTC. 

  - CVE-2019-5761: Use after free in SwiftShader.

  - CVE-2019-5762: Use after free in PDFium. 

  - CVE-2019-5763: Insufficient validation of untrusted
    input in V8.

  - CVE-2019-5764: Use after free in WebRTC. 

  - CVE-2019-5765: Insufficient policy enforcement in the
    browser.

  - CVE-2019-5766: Insufficient policy enforcement in
    Canvas.

  - CVE-2019-5767: Incorrect security UI in WebAPKs. 

  - CVE-2019-5768: Insufficient policy enforcement in
    DevTools. 

  - CVE-2019-5769: Insufficient validation of untrusted
    input in Blink.

  - CVE-2019-5770: Heap buffer overflow in WebGL. 

  - CVE-2019-5771: Heap buffer overflow in SwiftShader.

  - CVE-2019-5772: Use after free in PDFium. 

  - CVE-2019-5773: Insufficient data validation in
    IndexedDB.

  - CVE-2019-5774: Insufficient validation of untrusted
    input in SafeBrowsing. 

  - CVE-2019-5775: Insufficient policy enforcement in
    Omnibox. 

  - CVE-2019-5776: Insufficient policy enforcement in
    Omnibox. 

  - CVE-2019-5777: Insufficient policy enforcement in
    Omnibox. 

  - CVE-2019-5778: Insufficient policy enforcement in
    Extensions.

  - CVE-2019-5779: Insufficient policy enforcement in
    ServiceWorker.

  - CVE-2019-5780: Insufficient policy enforcement. 

  - CVE-2019-5781: Insufficient policy enforcement in
    Omnibox.

For a full list of changes refer to
https://chromereleases.googleblog.com/2019/02/stable-channel-update-fo
r-desktop.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124936"
  );
  # https://chromereleases.googleblog.com/2019/02/stable-channel-update-for-desktop.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/19");
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

if ( rpm_check(release:"SUSE15.0", reference:"chromedriver-72.0.3626.96-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromedriver-debuginfo-72.0.3626.96-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-72.0.3626.96-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-debuginfo-72.0.3626.96-lp150.2.41.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-debugsource-72.0.3626.96-lp150.2.41.1") ) flag++;

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
