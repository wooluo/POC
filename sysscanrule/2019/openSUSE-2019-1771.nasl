#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1771.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126904);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/22 10:22:10");

  script_cve_id("CVE-2017-17742", "CVE-2018-1000073", "CVE-2018-1000074", "CVE-2018-1000075", "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078", "CVE-2018-1000079", "CVE-2018-16395", "CVE-2018-16396", "CVE-2018-6914", "CVE-2018-8777", "CVE-2018-8778", "CVE-2018-8779", "CVE-2018-8780", "CVE-2019-8320", "CVE-2019-8321", "CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324", "CVE-2019-8325");

  script_name(english:"openSUSE Security Update : ruby-bundled-gems-rpmhelper / ruby2.5 (openSUSE-2019-1771)");
  script_summary(english:"Check for the openSUSE-2019-1771 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ruby2.5 and ruby-bundled-gems-rpmhelper fixes the
following issues :

Changes in ruby2.5 :

Update to 2.5.5 and 2.5.4 :

https://www.ruby-lang.org/en/news/2019/03/15/ruby-2-5-5-released/
https://www.ruby-lang.org/en/news/2019/03/13/ruby-2-5-4-released/

Security issues fixed :

  - CVE-2019-8320: Delete directory using symlink when
    decompressing tar (bsc#1130627)

  - CVE-2019-8321: Escape sequence injection vulnerability
    in verbose (bsc#1130623)

  - CVE-2019-8322: Escape sequence injection vulnerability
    in gem owner (bsc#1130622)

  - CVE-2019-8323: Escape sequence injection vulnerability
    in API response handling (bsc#1130620)

  - CVE-2019-8324: Installing a malicious gem may lead to
    arbitrary code execution (bsc#1130617)

  - CVE-2019-8325: Escape sequence injection vulnerability
    in errors (bsc#1130611)

Ruby 2.5 was updated to 2.5.3 :

This release includes some bug fixes and some security fixes.

Security issues fixed :

  - CVE-2018-16396: Tainted flags are not propagated in
    Array#pack and String#unpack with some directives
    (bsc#1112532)

  - CVE-2018-16395: OpenSSL::X509::Name equality check does
    not work correctly (bsc#1112530)

Ruby 2.5 was updated to 2.5.1 :

This release includes some bug fixes and some security fixes.

Security issues fixed :

  - CVE-2017-17742: HTTP response splitting in WEBrick
    (bsc#1087434)

  - CVE-2018-6914: Unintentional file and directory creation
    with directory traversal in tempfile and tmpdir
    (bsc#1087441)

  - CVE-2018-8777: DoS by large request in WEBrick
    (bsc#1087436)

  - CVE-2018-8778: Buffer under-read in String#unpack
    (bsc#1087433)

  - CVE-2018-8779: Unintentional socket creation by poisoned
    NUL byte in UNIXServer and UNIXSocket (bsc#1087440)

  - CVE-2018-8780: Unintentional directory traversal by
    poisoned NUL byte in Dir (bsc#1087437)

  - Multiple vulnerabilities in RubyGems were fixed :

  - CVE-2018-1000079: Fixed path traversal issue during gem
    installation allows to write to arbitrary filesystem
    locations (bsc#1082058)

  - CVE-2018-1000075: Fixed infinite loop vulnerability due
    to negative size in tar header causes Denial of Service
    (bsc#1082014)

  - CVE-2018-1000078: Fixed XSS vulnerability in homepage
    attribute when displayed via gem server (bsc#1082011)

  - CVE-2018-1000077: Fixed that missing URL validation on
    spec home attribute allows malicious gem to set an
    invalid homepage URL (bsc#1082010)

  - CVE-2018-1000076: Fixed improper verification of
    signatures in tarball allows to install mis-signed gem
    (bsc#1082009)

  - CVE-2018-1000074: Fixed unsafe Object Deserialization
    Vulnerability in gem owner allowing arbitrary code
    execution on specially crafted YAML (bsc#1082008)

  - CVE-2018-1000073: Fixed path traversal when writing to a
    symlinked basedir outside of the root (bsc#1082007)

Other changes :

  - Fixed Net::POPMail methods modify frozen literal when
    using default arg

  - ruby: change over of the Japanese Era to the new emperor
    May 1st 2019 (bsc#1133790)

  - build with PIE support (bsc#1130028)

Changes in ruby-bundled-gems-rpmhelper :

  - Add a new helper for bundled ruby gems.

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ruby-lang.org/en/news/2019/03/13/ruby-2-5-4-released/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ruby-lang.org/en/news/2019/03/15/ruby-2-5-5-released/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ruby-bundled-gems-rpmhelper / ruby2.5 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libruby2_5-2_5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libruby2_5-2_5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-bundled-gems-rpmhelper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-devel-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-doc-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-stdlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
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
if (release !~ "^(SUSE15\.0|SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libruby2_5-2_5-2.5.5-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libruby2_5-2_5-debuginfo-2.5.5-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ruby-bundled-gems-rpmhelper-0.0.2-lp150.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ruby2.5-2.5.5-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ruby2.5-debuginfo-2.5.5-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ruby2.5-debugsource-2.5.5-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ruby2.5-devel-2.5.5-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ruby2.5-devel-extra-2.5.5-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ruby2.5-doc-ri-2.5.5-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ruby2.5-stdlib-2.5.5-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ruby2.5-stdlib-debuginfo-2.5.5-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libruby2_5-2_5-2.5.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libruby2_5-2_5-debuginfo-2.5.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby-bundled-gems-rpmhelper-0.0.2-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby2.5-2.5.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby2.5-debuginfo-2.5.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby2.5-debugsource-2.5.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby2.5-devel-2.5.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby2.5-devel-extra-2.5.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby2.5-doc-ri-2.5.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby2.5-stdlib-2.5.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby2.5-stdlib-debuginfo-2.5.5-lp151.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby-bundled-gems-rpmhelper / libruby2_5-2_5 / etc");
}
