#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1561.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(125982);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/20 11:24:24");

  script_cve_id("CVE-2019-12735");

  script_name(english:"openSUSE Security Update : vim (openSUSE-2019-1561)");
  script_summary(english:"Check for the openSUSE-2019-1561 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for vim fixes the following issue :

Security issue fixed :

  - CVE-2019-12735: Fixed a potential arbitrary code
    execution vulnerability in getchar.c (bsc#1137443).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137443"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected vim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-data-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/18");
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

if ( rpm_check(release:"SUSE15.0", reference:"gvim-8.0.1568-lp150.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gvim-debuginfo-8.0.1568-lp150.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vim-8.0.1568-lp150.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vim-data-8.0.1568-lp150.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vim-data-common-8.0.1568-lp150.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vim-debuginfo-8.0.1568-lp150.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vim-debugsource-8.0.1568-lp150.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gvim-8.0.1568-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gvim-debuginfo-8.0.1568-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vim-8.0.1568-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vim-data-8.0.1568-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vim-data-common-8.0.1568-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vim-debuginfo-8.0.1568-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vim-debugsource-8.0.1568-lp151.5.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gvim / gvim-debuginfo / vim / vim-data / vim-data-common / etc");
}
