#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-310.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(122746);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/11  9:41:59");

  script_cve_id("CVE-2019-3825");

  script_name(english:"openSUSE Security Update : gdm (openSUSE-2019-310)");
  script_summary(english:"Check for the openSUSE-2019-310 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gdm fixes the following issues :

Security issue fixed :

  - CVE-2019-3825: Fixed a lock screen bypass when timed
    login was enabled (bsc#1124628).

Other issues fixed :

  - GLX applications do not work well when the proprietary
    nvidia driver is used with a wayland session. Because of
    that this update disables wayland on that hardware
    (bsc#1112578).

  - Fixed an issue where gdm restart fails to kill user
    processes (bsc#1112294 and bsc#1113245).

  - Fixed a System halt in the screen with message 'End of
    ORACLE section' (bsc#1120307).

  - Fixed an issue which did not allow the returning to text
    console when gdm is stopped (bsc#1113700).&#9;

  - Fixed an issue which was causing system hang during the
    load of gdm (bsc#1112578).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124628"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gdm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdm-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdmflexiserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdm1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Gdm-1_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/11");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"gdm-3.26.2.1-lp150.11.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gdm-branding-upstream-3.26.2.1-lp150.11.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gdm-debuginfo-3.26.2.1-lp150.11.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gdm-debugsource-3.26.2.1-lp150.11.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gdm-devel-3.26.2.1-lp150.11.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gdm-lang-3.26.2.1-lp150.11.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"gdmflexiserver-3.26.2.1-lp150.11.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgdm1-3.26.2.1-lp150.11.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgdm1-debuginfo-3.26.2.1-lp150.11.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-Gdm-1_0-3.26.2.1-lp150.11.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdm / gdm-branding-upstream / gdm-debuginfo / gdm-debugsource / etc");
}
