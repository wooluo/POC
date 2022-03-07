#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1520.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(125758);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/07  9:45:01");

  script_cve_id("CVE-2019-9704", "CVE-2019-9705");

  script_name(english:"openSUSE Security Update : cronie (openSUSE-2019-1520)");
  script_summary(english:"Check for the openSUSE-2019-1520 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for cronie fixes the following issues :

Security issues fixed :

  - CVE-2019-9704: Fixed an insufficient check in the return
    value of calloc which could allow a local user to create
    Denial of Service by crashing the daemon (bsc#1128937).

  - CVE-2019-9705: Fixed an implementation vulnerability
    which could allow a local user to exhaust the memory
    resulting in Denial of Service (bsc#1128935). 

Bug fixes :

  - Manual start of cron is possible even when it's already
    started using systemd (bsc#1133100).

  - Cron schedules only one job of crontab (bsc#1130746).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133100"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cronie packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cronie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cronie-anacron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cronie-anacron-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cronie-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cronie-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/07");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"cron-4.2-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"cronie-1.5.1-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"cronie-anacron-1.5.1-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"cronie-anacron-debuginfo-1.5.1-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"cronie-debuginfo-1.5.1-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"cronie-debugsource-1.5.1-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cron-4.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cronie-1.5.1-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cronie-anacron-1.5.1-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cronie-anacron-debuginfo-1.5.1-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cronie-debuginfo-1.5.1-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cronie-debugsource-1.5.1-lp151.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cron / cronie / cronie-anacron / cronie-anacron-debuginfo / etc");
}
