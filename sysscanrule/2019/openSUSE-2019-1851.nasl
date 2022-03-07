#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1851.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(127883);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/20 11:58:13");

  script_cve_id("CVE-2019-14744");

  script_name(english:"openSUSE Security Update : kconfig / kdelibs4 (openSUSE-2019-1851)");
  script_summary(english:"Check for the openSUSE-2019-1851 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for kconfig, kdelibs4 fixes the following issues :

  - CVE-2019-14744: Fixed a command execution by an shell
    expansion (boo#1144600)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144600"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kconfig / kdelibs4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kconf_update5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kconf_update5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kconfig-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kconfig-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kconfig-devel-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kconfig-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-doc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libKF5ConfigCore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libKF5ConfigCore5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libKF5ConfigCore5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libKF5ConfigCore5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libKF5ConfigCore5-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libKF5ConfigGui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libKF5ConfigGui5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libKF5ConfigGui5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libKF5ConfigGui5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/14");
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

if ( rpm_check(release:"SUSE15.0", reference:"kconf_update5-5.45.0-lp150.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kconf_update5-debuginfo-5.45.0-lp150.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kconfig-debugsource-5.45.0-lp150.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kconfig-devel-5.45.0-lp150.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kconfig-devel-debuginfo-5.45.0-lp150.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kdelibs4-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kdelibs4-apidocs-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kdelibs4-branding-upstream-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kdelibs4-core-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kdelibs4-core-debuginfo-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kdelibs4-debuginfo-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kdelibs4-debugsource-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kdelibs4-doc-debuginfo-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libKF5ConfigCore5-5.45.0-lp150.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libKF5ConfigCore5-debuginfo-5.45.0-lp150.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libKF5ConfigCore5-lang-5.45.0-lp150.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libKF5ConfigGui5-5.45.0-lp150.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libKF5ConfigGui5-debuginfo-5.45.0-lp150.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libkde4-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libkde4-debuginfo-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libkde4-devel-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libkde4-devel-debuginfo-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libkdecore4-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libkdecore4-debuginfo-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libkdecore4-devel-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libkdecore4-devel-debuginfo-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libksuseinstall-devel-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libksuseinstall1-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libksuseinstall1-debuginfo-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"kconfig-devel-32bit-5.45.0-lp150.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"kconfig-devel-32bit-debuginfo-5.45.0-lp150.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libKF5ConfigCore5-32bit-5.45.0-lp150.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libKF5ConfigCore5-32bit-debuginfo-5.45.0-lp150.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libKF5ConfigGui5-32bit-5.45.0-lp150.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libKF5ConfigGui5-32bit-debuginfo-5.45.0-lp150.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libkde4-32bit-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libkde4-32bit-debuginfo-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libkdecore4-32bit-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libkdecore4-32bit-debuginfo-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libksuseinstall1-32bit-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libksuseinstall1-32bit-debuginfo-4.14.38-lp150.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kconf_update5-5.55.0-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kconf_update5-debuginfo-5.55.0-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kconfig-debugsource-5.55.0-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kconfig-devel-5.55.0-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kconfig-devel-debuginfo-5.55.0-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kdelibs4-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kdelibs4-apidocs-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kdelibs4-branding-upstream-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kdelibs4-core-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kdelibs4-core-debuginfo-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kdelibs4-debuginfo-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kdelibs4-debugsource-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kdelibs4-doc-debuginfo-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libKF5ConfigCore5-5.55.0-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libKF5ConfigCore5-debuginfo-5.55.0-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libKF5ConfigCore5-lang-5.55.0-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libKF5ConfigGui5-5.55.0-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libKF5ConfigGui5-debuginfo-5.55.0-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libkde4-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libkde4-debuginfo-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libkde4-devel-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libkde4-devel-debuginfo-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libkdecore4-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libkdecore4-debuginfo-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libkdecore4-devel-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libkdecore4-devel-debuginfo-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libksuseinstall-devel-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libksuseinstall1-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libksuseinstall1-debuginfo-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"kconfig-devel-32bit-5.55.0-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"kconfig-devel-32bit-debuginfo-5.55.0-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libKF5ConfigCore5-32bit-5.55.0-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libKF5ConfigCore5-32bit-debuginfo-5.55.0-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libKF5ConfigGui5-32bit-5.55.0-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libKF5ConfigGui5-32bit-debuginfo-5.55.0-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libkde4-32bit-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libkde4-32bit-debuginfo-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libkdecore4-32bit-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libkdecore4-32bit-debuginfo-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libksuseinstall1-32bit-4.14.38-lp151.9.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libksuseinstall1-32bit-debuginfo-4.14.38-lp151.9.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kconf_update5 / kconf_update5-debuginfo / kconfig-debugsource / etc");
}
