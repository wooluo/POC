#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1904.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(127996);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/20 11:58:10");

  script_cve_id("CVE-2019-10162", "CVE-2019-10163", "CVE-2019-10203");

  script_name(english:"openSUSE Security Update : pdns (openSUSE-2019-1904)");
  script_summary(english:"Check for the openSUSE-2019-1904 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for pdns fixes the following issues :

Security issues fixed :

  - CVE-2019-10203: Updated PostgreSQL schema to address a
    possible denial of service by an authorized user by
    inserting a crafted record in a MASTER type zone under
    their control. (boo#1142810)

  - CVE-2019-10162: Fixed a denial of service but when
    authorized user to cause the server to exit by inserting
    a crafted record in a MASTER type zone under their
    control. (boo#1138582)

  - CVE-2019-10163: Fixed a denial of service of slave
    server when an authorized master server sends large
    number of NOTIFY messages. (boo#1138582) &#9;
    Non-security issues fixed :

  - Enabled the option to disable superslave support.

  - Fixed `pdnsutil b2b-migrate` to not lose NSEC3 settings."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142810"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pdns packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-geoip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-godbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-godbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-mydns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-mydns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-remote-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-sqlite3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"pdns-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-geoip-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-geoip-debuginfo-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-godbc-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-godbc-debuginfo-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-ldap-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-ldap-debuginfo-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-lua-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-lua-debuginfo-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-mydns-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-mydns-debuginfo-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-mysql-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-mysql-debuginfo-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-postgresql-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-postgresql-debuginfo-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-remote-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-remote-debuginfo-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-sqlite3-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-sqlite3-debuginfo-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-debuginfo-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-debugsource-4.1.2-lp150.3.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-backend-geoip-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-backend-geoip-debuginfo-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-backend-godbc-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-backend-godbc-debuginfo-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-backend-ldap-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-backend-ldap-debuginfo-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-backend-lua-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-backend-lua-debuginfo-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-backend-mydns-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-backend-mydns-debuginfo-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-backend-mysql-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-backend-mysql-debuginfo-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-backend-postgresql-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-backend-postgresql-debuginfo-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-backend-remote-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-backend-remote-debuginfo-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-backend-sqlite3-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-backend-sqlite3-debuginfo-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-debuginfo-4.1.8-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-debugsource-4.1.8-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pdns / pdns-backend-geoip / pdns-backend-geoip-debuginfo / etc");
}
