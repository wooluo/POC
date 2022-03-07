#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1689.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126490);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/09 10:56:49");

  script_cve_id("CVE-2019-11768", "CVE-2019-12616");

  script_name(english:"openSUSE Security Update : phpMyAdmin (openSUSE-2019-1689)");
  script_summary(english:"Check for the openSUSE-2019-1689 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for phpMyAdmin fixes the following issues :

phpMyAdmin was updated to 4.9.0.1 :

  - Several issues with SYSTEM VERSIONING tables

  - Fixed json encode error in export

  - Fixed JavaScript events not activating on input (sql
    bookmark issue)

  - Show Designer combo boxes when adding a constraint

  - Fix edit view

  - Fixed invalid default value for bit field

  - Fix several errors relating to GIS data types

  - Fixed JavaScript error PMA_messages is not defined

  - Fixed import XML data with leading zeros

  - Fixed php notice, added support for 'DELETE HISTORY'
    table privilege (MariaDB >= 10.3.4)

  - Fixed MySQL 8.0.0 issues with GIS display

  - Fixed 'Server charset' in 'Database server' tab showing
    wrong information

  - Fixed can not copy user on Percona Server 5.7

  - Updated sql-parser to version 4.3.2, which fixes several
    parsing and linting problems

  - boo#1137497 / PMASA-2019-4 / CVE-2019-12616 / CWE-661:
    Fixed CSRF vulnerability in login form
    https://www.phpmyadmin.net/security/PMASA-2019-4/

  - boo#1137496 / PMASA-2019-3 / CVE-2019-11768 / CWE-661:
    Fixed SQL injection in Designer feature
    https://www.phpmyadmin.net/security/PMASA-2019-3/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2019-3/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2019-4/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

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



flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"phpMyAdmin-4.9.0.1-lp150.31.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"phpMyAdmin-4.9.0.1-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
