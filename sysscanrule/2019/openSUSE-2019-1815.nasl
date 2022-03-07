#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1815.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(127735);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2018-20073", "CVE-2019-5847", "CVE-2019-5848");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2019-1815)");
  script_summary(english:"Check for the openSUSE-2019-1815 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for chromium to version 75.0.3770.142 fixes the following
issues :

Security issue fixed :

  - CVE-2019-5847: V8 sealed/frozen elements cause crash
    (boo#1141649).

  - CVE-2019-5848: Font sizes may expose sensitive
    information (boo#1141649).

  - CVE-2018-20073: Fixed information leaks of URL metadata
    nad passwords via extended filesystem attributes
    (boo#1120892).

Non-security fix :

  - Fixed a segfault on startup (boo#1141102)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141649"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/27");
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

if ( rpm_check(release:"SUSE15.0", reference:"chromedriver-75.0.3770.142-lp150.221.4") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromedriver-debuginfo-75.0.3770.142-lp150.221.4") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-75.0.3770.142-lp150.221.4") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-debuginfo-75.0.3770.142-lp150.221.4") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-debugsource-75.0.3770.142-lp150.221.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-75.0.3770.142-lp151.2.12.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-debuginfo-75.0.3770.142-lp151.2.12.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-75.0.3770.142-lp151.2.12.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-debuginfo-75.0.3770.142-lp151.2.12.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-debugsource-75.0.3770.142-lp151.2.12.4") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
