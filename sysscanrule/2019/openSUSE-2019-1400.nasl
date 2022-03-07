#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1400.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(125213);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/16 10:38:53");

  script_cve_id("CVE-2018-16877", "CVE-2018-16878", "CVE-2019-3885");

  script_name(english:"openSUSE Security Update : pacemaker (openSUSE-2019-1400)");
  script_summary(english:"Check for the openSUSE-2019-1400 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for pacemaker fixes the following issues :

Security issues fixed :

  - CVE-2019-3885: Fixed an information disclosure in log
    output. (bsc#1131357)

  - CVE-2018-16877: Fixed a local privilege escalation
    through insufficient IPC client-server authentication.
    (bsc#1131356)

  - CVE-2018-16878: Fixed a denial of service through
    insufficient verification inflicted preference of
    uncontrolled processes. (bsc#1131353)

Non-security issue fixed :

  - crmd: delete resource from lrmd when appropriate to
    avoid timeouts with crmsh (bsc#1117381).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131357"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pacemaker packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpacemaker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpacemaker3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpacemaker3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-cli-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-cts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-remote-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/16");
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

if ( rpm_check(release:"SUSE15.0", reference:"libpacemaker-devel-1.1.18+20180430.b12c320f5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libpacemaker3-1.1.18+20180430.b12c320f5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libpacemaker3-debuginfo-1.1.18+20180430.b12c320f5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pacemaker-1.1.18+20180430.b12c320f5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pacemaker-cli-1.1.18+20180430.b12c320f5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pacemaker-cli-debuginfo-1.1.18+20180430.b12c320f5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pacemaker-cts-1.1.18+20180430.b12c320f5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pacemaker-debuginfo-1.1.18+20180430.b12c320f5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pacemaker-debugsource-1.1.18+20180430.b12c320f5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pacemaker-remote-1.1.18+20180430.b12c320f5-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pacemaker-remote-debuginfo-1.1.18+20180430.b12c320f5-lp150.2.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpacemaker-devel / libpacemaker3 / libpacemaker3-debuginfo / etc");
}
