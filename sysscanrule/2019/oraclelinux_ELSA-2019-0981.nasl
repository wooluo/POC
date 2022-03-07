#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:0981 and 
# Oracle Linux Security Advisory ELSA-2019-0981 respectively.
#

include("compat.inc");

if (description)
{
  script_id(127571);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-7164", "CVE-2019-7548", "CVE-2019-9636");
  script_xref(name:"RHSA", value:"2019:0981");

  script_name(english:"Oracle Linux 8 : python27:2.7 (ELSA-2019-0981)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2019:0981 :

An update for the python27:2.7 module is now available for Red Hat
Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Python is an interpreted, interactive, object-oriented programming
language that supports modules, classes, exceptions, high-level
dynamic data types, and dynamic typing.

SQLAlchemy is an Object Relational Mapper (ORM) that provides a
flexible, high-level interface to SQL databases.

Security Fix(es) :

* python: Information Disclosure due to urlsplit improper NFKC
normalization (CVE-2019-9636)

* python-sqlalchemy: SQL Injection when the order_by parameter can be
controlled (CVE-2019-7164)

* python-sqlalchemy: SQL Injection when the group_by parameter can be
controlled (CVE-2019-7548)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-August/008961.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python27:2.7 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-nose-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-sqlalchemy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-Cython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-attrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-backports");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-backports-ssl_match_hostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-coverage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-docs-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-docutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-funcsigs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-ipaddress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-mock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-nose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pluggy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-psycopg2-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pygments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pymongo-gridfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pytest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pytest-mock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pytz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-setuptools_scm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-sqlalchemy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-virtualenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-wheel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 8", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"babel-2.5.1-9.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python-nose-docs-1.3.7-30.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python-psycopg2-doc-2.7.5-7.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python-sqlalchemy-doc-1.3.2-1.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-2.7.15-22.0.1.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-Cython-0.28.1-7.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-PyMySQL-0.8.0-10.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-attrs-17.4.0-10.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-babel-2.5.1-9.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-backports-1.0-15.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-backports-ssl_match_hostname-3.5.0.1-11.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-bson-3.6.1-9.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-chardet-3.0.4-10.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-coverage-4.5.1-4.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-debug-2.7.15-22.0.1.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-devel-2.7.15-22.0.1.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-dns-1.15.0-9.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-docs-2.7.15-4.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-docs-info-2.7.15-4.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-docutils-0.14-12.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-funcsigs-1.0.2-13.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-idna-2.5-7.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-ipaddress-1.0.18-6.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-jinja2-2.10-8.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-libs-2.7.15-22.0.1.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-lxml-4.2.3-3.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-markupsafe-0.23-19.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-mock-2.0.0-13.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-nose-1.3.7-30.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-numpy-1.14.2-10.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-numpy-doc-1.14.2-10.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-numpy-f2py-1.14.2-10.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-pip-9.0.3-13.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-pluggy-0.6.0-8.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-psycopg2-2.7.5-7.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-psycopg2-debug-2.7.5-7.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-psycopg2-tests-2.7.5-7.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-py-1.5.3-6.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-pygments-2.2.0-20.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-pymongo-3.6.1-9.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-pymongo-gridfs-3.6.1-9.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-pysocks-1.6.8-6.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-pytest-3.4.2-13.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-pytest-mock-1.9.0-4.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-pytz-2017.2-12.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-pyyaml-3.12-16.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-requests-2.20.0-2.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-rpm-macros-3-38.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-scipy-1.0.0-19.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-setuptools-39.0.1-11.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-setuptools_scm-1.15.7-6.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-six-1.11.0-5.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-sqlalchemy-1.3.2-1.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-test-2.7.15-22.0.1.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-tkinter-2.7.15-22.0.1.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-tools-2.7.15-22.0.1.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-urllib3-1.23-7.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-virtualenv-15.1.0-18.module+el8.0.0+5233+93973c75")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python2-wheel-0.30.0-13.module+el8.0.0+5233+93973c75")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "babel / python-nose-docs / python-psycopg2-doc / etc");
}
