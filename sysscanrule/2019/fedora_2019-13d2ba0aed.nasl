#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-13d2ba0aed.
#

include("compat.inc");

if (description)
{
  script_id(125906);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/18 10:31:32");

  script_cve_id("CVE-2019-11768", "CVE-2019-12616");
  script_xref(name:"FEDORA", value:"2019-13d2ba0aed");

  script_name(english:"Fedora 30 : php-phpmyadmin-sql-parser / phpMyAdmin (2019-13d2ba0aed)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Upstream announcement :

Welcome to **phpMyAdmin 4.9.0.1**, a bugfix release that includes
important security fixes.

This release fixes two security vulnerabilities :

  - PMASA-2019-3 is a SQL injection flaw in the Designer
    feature

  - PMASA-2019-4 is a CSRF attack that's possible through
    the 'cookie' login form

Upgrading is highly recommended for all users. Using the 'http'
auth_type instead of 'cookie' can mitigate the CSRF attack.

The solution for the CSRF attack does remove the former functionality
to log in directly through URL parameters (as mentioned in FAQ 4.8,
such as
https://example.com/phpmyadmin/?pma_username=root&password=foo). Such
behavior was discouraged and is now removed. Other query parameters
work as expected; only pma_username and pma_password have been
removed.

This release also includes fixes for many bugs, including :

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

There are many, many more bug fixes thanks to the efforts of our
developers, Google Summer of Code applicants, and other contributors.

The phpMyAdmin team

----

**phpmyadmin/sql-parser version 4.3.2**

  - Fix redundant whitespaces in build() outputs (#228)

  - Fix incorrect error on DEFAULT keyword in ALTER
    operation (#229)

  - Fix incorrect outputs from Query::getClause (#233)

  - Add support for reading a SQL file from stdin

  - Fix for missing tokenize-query in Composer's vendor/bin/
    directory

  - Fix for PHP warnings with an incomplete CASE expression
    (#241)

  - Fix for error message with multiple CALL statements
    (#223)

  - Recognize the question mark character as a parameter
    (#242)

Note that WebRAY Network Security has extracted the preceding
description block directly from the Fedora update system website.
WebRAY has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-13d2ba0aed"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://example.com/phpmyadmin/?pma_username=root&password=foo"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected php-phpmyadmin-sql-parser and / or phpMyAdmin
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-phpmyadmin-sql-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"php-phpmyadmin-sql-parser-4.3.2-1.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"phpMyAdmin-4.9.0.1-1.fc30")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-phpmyadmin-sql-parser / phpMyAdmin");
}
