#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1914.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(128006);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/20 11:58:10");

  script_cve_id("CVE-2019-6133");

  script_name(english:"openSUSE Security Update : polkit (openSUSE-2019-1914)");
  script_summary(english:"Check for the openSUSE-2019-1914 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for polkit fixes the following issues :

Security issue fixed :

  - CVE-2019-6133: Fixed improper caching of auth decisions,
    which could bypass uid checking in the interactive
    backend (bsc#1121826).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121826"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected polkit packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpolkit0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpolkit0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpolkit0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpolkit0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:polkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:polkit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:polkit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:polkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:polkit-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Polkit-1_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");
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

if ( rpm_check(release:"SUSE15.0", reference:"libpolkit0-0.114-lp150.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libpolkit0-debuginfo-0.114-lp150.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"polkit-0.114-lp150.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"polkit-debuginfo-0.114-lp150.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"polkit-debugsource-0.114-lp150.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"polkit-devel-0.114-lp150.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"polkit-devel-debuginfo-0.114-lp150.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-Polkit-1_0-0.114-lp150.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libpolkit0-32bit-0.114-lp150.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libpolkit0-32bit-debuginfo-0.114-lp150.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpolkit0-0.114-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpolkit0-debuginfo-0.114-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"polkit-0.114-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"polkit-debuginfo-0.114-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"polkit-debugsource-0.114-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"polkit-devel-0.114-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"polkit-devel-debuginfo-0.114-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"typelib-1_0-Polkit-1_0-0.114-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libpolkit0-32bit-0.114-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libpolkit0-32bit-debuginfo-0.114-lp151.5.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpolkit0 / libpolkit0-debuginfo / polkit / polkit-debuginfo / etc");
}
