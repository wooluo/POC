#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1346.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(124711);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/09  9:52:01");

  script_cve_id("CVE-2019-11234", "CVE-2019-11235");

  script_name(english:"openSUSE Security Update : freeradius-server (openSUSE-2019-1346)");
  script_summary(english:"Check for the openSUSE-2019-1346 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for freeradius-server fixes the following issues :

Security issues fixed :

  - CVE-2019-11235: Fixed an authentication bypass related
    to the EAP-PWD Commit frame and insufficent validation
    of elliptic curve points (bsc#1132549).

  - CVE-2019-11234: Fixed an authentication bypass caused by
    reflecting privous values back to the server
    (bsc#1132664).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132664"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freeradius-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/09");
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

if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-debuginfo-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-debugsource-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-devel-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-krb5-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-krb5-debuginfo-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-ldap-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-ldap-debuginfo-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-libs-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-libs-debuginfo-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-mysql-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-mysql-debuginfo-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-perl-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-perl-debuginfo-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-postgresql-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-postgresql-debuginfo-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-python-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-python-debuginfo-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-sqlite-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-sqlite-debuginfo-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-utils-3.0.16-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"freeradius-server-utils-debuginfo-3.0.16-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius-server / freeradius-server-debuginfo / etc");
}
