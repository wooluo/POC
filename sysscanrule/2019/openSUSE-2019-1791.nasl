#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1791.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126975);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/24  9:40:16");

  script_cve_id("CVE-2018-11499", "CVE-2018-19797", "CVE-2018-19827", "CVE-2018-19837", "CVE-2018-19838", "CVE-2018-19839", "CVE-2018-20190", "CVE-2018-20821", "CVE-2018-20822", "CVE-2019-6283", "CVE-2019-6284", "CVE-2019-6286");

  script_name(english:"openSUSE Security Update : libsass (openSUSE-2019-1791)");
  script_summary(english:"Check for the openSUSE-2019-1791 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libsass to version 3.6.1 fixes the following issues :

Security issues fixed :

  - CVE-2019-6283: Fixed heap-buffer-overflow in
    Sass::Prelexer::parenthese_scope(char const*)
    (boo#1121943).

  - CVE-2019-6284: Fixed heap-based buffer over-read exists
    in Sass:Prelexer:alternatives (boo#1121944).

  - CVE-2019-6286: Fixed heap-based buffer over-read exists
    in Sass:Prelexer:skip_over_scopes (boo#1121945).

  - CVE-2018-11499: Fixed use-after-free vulnerability in
    sass_context.cpp:handle_error (boo#1096894).

  - CVE-2018-19797: Disallowed parent selector in
    selector_fns arguments (boo#1118301).

  - CVE-2018-19827: Fixed use-after-free vulnerability
    exists in the SharedPtr class (boo#1118346).

  - CVE-2018-19837: Fixed stack overflow in Eval::operator()
    (boo#1118348).

  - CVE-2018-19838: Fixed stack-overflow at
    IMPLEMENT_AST_OPERATORS expansion (boo#1118349).

  - CVE-2018-19839: Fixed buffer-overflow (OOB read) against
    some invalid input (boo#1118351).

  - CVE-2018-20190: Fixed NULL pointer dereference in
    Sass::Eval::operator()(Sass::Supports_Operator*)
    (boo#1119789).

  - CVE-2018-20821: Fixed uncontrolled recursion in
    Sass:Parser:parse_css_variable_value (boo#1133200).

  - CVE-2018-20822: Fixed stack-overflow at
    Sass::Inspect::operator() (boo#1133201)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133201"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libsass packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsass-3_6_1-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsass-3_6_1-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsass-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsass-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/24");
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

if ( rpm_check(release:"SUSE15.0", reference:"libsass-3_6_1-1-3.6.1-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsass-3_6_1-1-debuginfo-3.6.1-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsass-debugsource-3.6.1-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsass-devel-3.6.1-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsass-3_6_1-1-3.6.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsass-3_6_1-1-debuginfo-3.6.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsass-debugsource-3.6.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsass-devel-3.6.1-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsass-3_6_1-1 / libsass-3_6_1-1-debuginfo / libsass-debugsource / etc");
}
