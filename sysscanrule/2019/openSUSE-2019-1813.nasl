#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1813.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(127733);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-11709", "CVE-2019-11711", "CVE-2019-11712", "CVE-2019-11713", "CVE-2019-11715", "CVE-2019-11717", "CVE-2019-11719", "CVE-2019-11729", "CVE-2019-11730", "CVE-2019-9811");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2019-1813)");
  script_summary(english:"Check for the openSUSE-2019-1813 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaThunderbird version 60.8 fixes the following
issues :

Security issues fixed :

  - CVE-2019-9811: Sandbox escape via installation of
    malicious language pack (bsc#1140868).

  - CVE-2019-11711: Script injection within domain through
    inner window reuse (bsc#1140868).

  - CVE-2019-11712: Cross-origin POST requests can be made
    with NPAPI plugins by following 308 redirects
    (bsc#1140868).

  - CVE-2019-11713: Use-after-free with HTTP/2 cached stream
    (bsc#1140868).

  - CVE-2019-11729: Empty or malformed p256-ECDH public keys
    may trigger a segmentation fault (bsc#1140868).

  - CVE-2019-11715: HTML parsing error can contribute to
    content XSS (bsc#1140868).

  - CVE-2019-11717: Caret character improperly escaped in
    origins (bsc#1140868).

  - CVE-2019-11719: Out-of-bounds read when importing
    curve25519 private key (bsc#1140868).

  - CVE-2019-11730: Same-origin policy treats all files in a
    directory as having the same-origin (bsc#1140868).

  - CVE-2019-11709: Multiple Memory safety bugs fixed
    (bsc#1140868).

Non-security issued fixed :

  - Calendar: Problems when editing event times, some
    related to AM/PM setting in non-English locales

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140868"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
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
if (release !~ "^(SUSE15\.0|SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-60.8.0-lp150.3.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-buildsymbols-60.8.0-lp150.3.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-debuginfo-60.8.0-lp150.3.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-debugsource-60.8.0-lp150.3.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-translations-common-60.8.0-lp150.3.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-translations-other-60.8.0-lp150.3.48.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-60.8.0-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-buildsymbols-60.8.0-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-debuginfo-60.8.0-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-debugsource-60.8.0-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-translations-common-60.8.0-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-translations-other-60.8.0-lp151.2.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird / MozillaThunderbird-buildsymbols / etc");
}
