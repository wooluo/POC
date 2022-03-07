#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-155.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(122091);
  script_version("1.2");
  script_cvs_date("Date: 2019/03/27 11:14:35");

  script_cve_id("CVE-2018-20406", "CVE-2019-5010");

  script_name(english:"openSUSE Security Update : python3 (openSUSE-2019-155)");
  script_summary(english:"Check for the openSUSE-2019-155 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for python3 fixes the following issues :

Security issue fixed :

  - CVE-2019-5010: Fixed a denial-of-service vulnerability
    in the X509 certificate parser (bsc#1122191)

  - CVE-2018-20406: Fixed a integer overflow via a large
    LONG_BINPUT (bsc#1120644)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122191"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_6m1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_6m1_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_6m1_0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_6m1_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-curses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-dbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-dbm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-testsuite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/11");
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

if ( rpm_check(release:"SUSE15.0", reference:"libpython3_6m1_0-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libpython3_6m1_0-debuginfo-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-base-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-base-debuginfo-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-base-debugsource-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-curses-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-curses-debuginfo-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-dbm-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-dbm-debuginfo-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-debuginfo-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-debugsource-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-devel-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-devel-debuginfo-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-idle-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-testsuite-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-testsuite-debuginfo-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-tk-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-tk-debuginfo-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-tools-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libpython3_6m1_0-32bit-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libpython3_6m1_0-32bit-debuginfo-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"python3-32bit-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"python3-32bit-debuginfo-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"python3-base-32bit-3.6.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"python3-base-32bit-debuginfo-3.6.5-lp150.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpython3_6m1_0 / libpython3_6m1_0-32bit / etc");
}
