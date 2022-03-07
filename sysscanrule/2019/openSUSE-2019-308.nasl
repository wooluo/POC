#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-308.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(122744);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/02 21:54:17");

  script_cve_id("CVE-2018-4437", "CVE-2018-4438", "CVE-2018-4441", "CVE-2018-4442", "CVE-2018-4443", "CVE-2018-4464", "CVE-2019-6212", "CVE-2019-6215", "CVE-2019-6216", "CVE-2019-6217", "CVE-2019-6226", "CVE-2019-6227", "CVE-2019-6229", "CVE-2019-6233", "CVE-2019-6234");

  script_name(english:"openSUSE Security Update : webkit2gtk3 (openSUSE-2019-308)");
  script_summary(english:"Check for the openSUSE-2019-308 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for webkit2gtk3 to version 2.22.6 fixes the following
issues (boo#1124937 boo#1119558) :

Security vulnerabilities fixed :

  - CVE-2018-4437: Processing maliciously crafted web
    content may lead to arbitrary code execution. Multiple
    memory corruption issues were addressed with improved
    memory handling. (boo#1119553)

  - CVE-2018-4438: Processing maliciously crafted web
    content may lead to arbitrary code execution. A logic
    issue existed resulting in memory corruption. This was
    addressed with improved state management. (boo#1119554)

  - CVE-2018-4441: Processing maliciously crafted web
    content may lead to arbitrary code execution. A memory
    corruption issue was addressed with improved memory
    handling. (boo#1119555)

  - CVE-2018-4442: Processing maliciously crafted web
    content may lead to arbitrary code execution. A memory
    corruption issue was addressed with improved memory
    handling. (boo#1119556)

  - CVE-2018-4443: Processing maliciously crafted web
    content may lead to arbitrary code execution. A memory
    corruption issue was addressed with improved memory
    handling. (boo#1119557)

  - CVE-2018-4464: Processing maliciously crafted web
    content may lead to arbitrary code execution. Multiple
    memory corruption issues were addressed with improved
    memory handling. (boo#1119558)

  - CVE-2019-6212: Processing maliciously crafted web
    content may lead to arbitrary code execution. Multiple
    memory corruption issues were addressed with improved
    memory handling.

  - CVE-2019-6215: Processing maliciously crafted web
    content may lead to arbitrary code execution. A type
    confusion issue was addressed with improved memory
    handling.

  - CVE-2019-6216: Processing maliciously crafted web
    content may lead to arbitrary code execution. Multiple
    memory corruption issues were addressed with improved
    memory handling.

  - CVE-2019-6217: Processing maliciously crafted web
    content may lead to arbitrary code execution. Multiple
    memory corruption issues were addressed with improved
    memory handling.

  - CVE-2019-6226: Processing maliciously crafted web
    content may lead to arbitrary code execution. Multiple
    memory corruption issues were addressed with improved
    memory handling.

  - CVE-2019-6227: Processing maliciously crafted web
    content may lead to arbitrary code execution. A memory
    corruption issue was addressed with improved memory
    handling.

  - CVE-2019-6229: Processing maliciously crafted web
    content may lead to universal cross site scripting. A
    logic issue was addressed with improved validation.

  - CVE-2019-6233: Processing maliciously crafted web
    content may lead to arbitrary code execution. A memory
    corruption issue was addressed with improved memory
    handling.

  - CVE-2019-6234: Processing maliciously crafted web
    content may lead to arbitrary code execution. A memory
    corruption issue was addressed with improved memory
    handling.

Other bug fixes and changes :

  - Make kinetic scrolling slow down smoothly when reaching
    the ends of pages, instead of abruptly, to better match
    the GTK+ behaviour.

  - Fix Web inspector magnifier under Wayland.

  - Fix garbled rendering of some websites (e.g. YouTube)
    while scrolling under X11.

  - Fix several crashes, race conditions, and rendering
    issues.

For a detailed list of changes, please refer to :

- https://webkitgtk.org/security/WSA-2019-0001.html

- https://webkitgtk.org/2019/02/09/webkitgtk2.22.6-released.html

- https://webkitgtk.org/security/WSA-2018-0009.html

- https://webkitgtk.org/2018/12/13/webkitgtk2.22.5-released.html

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://webkitgtk.org/2018/12/13/webkitgtk2.22.5-released.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://webkitgtk.org/2019/02/09/webkitgtk2.22.6-released.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://webkitgtk.org/security/WSA-2018-0009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://webkitgtk.org/security/WSA-2019-0001.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected webkit2gtk3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk3-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-JavaScriptCore-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-WebKit2-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-WebKit2WebExtension-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit-jsc-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit-jsc-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk-4_0-injected-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk-4_0-injected-bundles-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-minibrowser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-minibrowser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-plugin-process-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-plugin-process-gtk2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/11");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libjavascriptcoregtk-4_0-18-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwebkit2gtk-4_0-37-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwebkit2gtk-4_0-37-debuginfo-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwebkit2gtk3-lang-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-JavaScriptCore-4_0-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-WebKit2-4_0-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-WebKit2WebExtension-4_0-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit-jsc-4-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit-jsc-4-debuginfo-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk-4_0-injected-bundles-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-debugsource-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-devel-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-minibrowser-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-minibrowser-debuginfo-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-plugin-process-gtk2-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"webkit2gtk3-plugin-process-gtk2-debuginfo-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-32bit-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-32bit-debuginfo-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-32bit-2.22.6-lp150.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-32bit-debuginfo-2.22.6-lp150.2.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libjavascriptcoregtk-4_0-18 / libjavascriptcoregtk-4_0-18-32bit / etc");
}
