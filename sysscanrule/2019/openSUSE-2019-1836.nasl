#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1836.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(127741);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2017-7418", "CVE-2019-12815");

  script_name(english:"openSUSE Security Update : proftpd (openSUSE-2019-1836)");
  script_summary(english:"Check for the openSUSE-2019-1836 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for proftpd fixes the following issues :

Security issues fixed :

  - CVE-2019-12815: Fixed arbitrary file copy in mod_copy
    that allowed for remote code execution and information
    disclosure without authentication (bnc#1142281)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142281"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected proftpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-radius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-radius-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/08");
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

if ( rpm_check(release:"SUSE15.0", reference:"proftpd-1.3.5e-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"proftpd-debuginfo-1.3.5e-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"proftpd-debugsource-1.3.5e-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"proftpd-devel-1.3.5e-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"proftpd-lang-1.3.5e-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"proftpd-ldap-1.3.5e-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"proftpd-ldap-debuginfo-1.3.5e-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"proftpd-mysql-1.3.5e-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"proftpd-mysql-debuginfo-1.3.5e-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"proftpd-pgsql-1.3.5e-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"proftpd-pgsql-debuginfo-1.3.5e-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"proftpd-radius-1.3.5e-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"proftpd-radius-debuginfo-1.3.5e-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"proftpd-sqlite-1.3.5e-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"proftpd-sqlite-debuginfo-1.3.5e-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-1.3.5e-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-debuginfo-1.3.5e-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-debugsource-1.3.5e-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-devel-1.3.5e-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-lang-1.3.5e-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-ldap-1.3.5e-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-ldap-debuginfo-1.3.5e-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-mysql-1.3.5e-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-mysql-debuginfo-1.3.5e-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-pgsql-1.3.5e-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-pgsql-debuginfo-1.3.5e-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-radius-1.3.5e-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-radius-debuginfo-1.3.5e-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-sqlite-1.3.5e-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"proftpd-sqlite-debuginfo-1.3.5e-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "proftpd / proftpd-debuginfo / proftpd-debugsource / proftpd-devel / etc");
}
