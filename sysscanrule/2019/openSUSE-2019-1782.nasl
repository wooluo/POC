#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1782.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126912);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/25  9:40:30");

  script_cve_id("CVE-2019-11709", "CVE-2019-11711", "CVE-2019-11712", "CVE-2019-11713", "CVE-2019-11715", "CVE-2019-11717", "CVE-2019-11719", "CVE-2019-11729", "CVE-2019-11730", "CVE-2019-9811");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2019-1782)");
  script_summary(english:"Check for the openSUSE-2019-1782 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaFirefox, mozilla-nss fixes the following 
issues :

MozillaFirefox to version ESR 60.8 :

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

mozilla-nss to version 3.44.1 :

  - Added IPSEC IKE support to softoken 

  - Many new FIPS test cases

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140868"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/22");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libfreebl3-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libfreebl3-debuginfo-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libfreebl3-hmac-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsoftokn3-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsoftokn3-debuginfo-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsoftokn3-hmac-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-certs-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-certs-debuginfo-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-debuginfo-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-debugsource-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-devel-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-sysinit-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-sysinit-debuginfo-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-tools-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-tools-debuginfo-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"MozillaFirefox-60.8.0-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"MozillaFirefox-branding-upstream-60.8.0-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"MozillaFirefox-buildsymbols-60.8.0-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-60.8.0-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"MozillaFirefox-debugsource-60.8.0-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"MozillaFirefox-devel-60.8.0-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"MozillaFirefox-translations-common-60.8.0-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"MozillaFirefox-translations-other-60.8.0-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libfreebl3-32bit-debuginfo-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libfreebl3-hmac-32bit-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsoftokn3-32bit-debuginfo-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsoftokn3-hmac-32bit-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nss-32bit-debuginfo-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-debuginfo-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.44.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-debuginfo-3.44.1-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-upstream / etc");
}
