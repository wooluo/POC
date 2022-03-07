#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1671.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126371);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/01 11:41:23");

  script_cve_id("CVE-2019-12749");

  script_name(english:"openSUSE Security Update : dbus-1 (openSUSE-2019-1671)");
  script_summary(english:"Check for the openSUSE-2019-1671 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for dbus-1 fixes the following issue :

Security issue fixed :

  - CVE-2019-12749: Fixed an implementation flaw in
    DBUS_COOKIE_SHA1 which could have allowed local
    attackers to bypass authentication (bsc#1137832). This
    update was imported from the SUSE:SLE-15:Update update
    project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137832"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dbus-1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-x11-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdbus-1-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdbus-1-3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdbus-1-3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdbus-1-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/01");
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

if ( rpm_check(release:"SUSE15.0", reference:"dbus-1-1.12.2-lp150.2.4.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dbus-1-debuginfo-1.12.2-lp150.2.4.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dbus-1-debugsource-1.12.2-lp150.2.4.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dbus-1-devel-1.12.2-lp150.2.4.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dbus-1-x11-1.12.2-lp150.2.4.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dbus-1-x11-debuginfo-1.12.2-lp150.2.4.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"dbus-1-x11-debugsource-1.12.2-lp150.2.4.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libdbus-1-3-1.12.2-lp150.2.4.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libdbus-1-3-debuginfo-1.12.2-lp150.2.4.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"dbus-1-32bit-debuginfo-1.12.2-lp150.2.4.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"dbus-1-devel-32bit-1.12.2-lp150.2.4.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libdbus-1-3-32bit-1.12.2-lp150.2.4.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libdbus-1-3-32bit-debuginfo-1.12.2-lp150.2.4.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dbus-1-x11 / dbus-1-x11-debuginfo / dbus-1-x11-debugsource / dbus-1 / etc");
}
