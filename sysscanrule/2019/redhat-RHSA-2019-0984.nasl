#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:0984. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124670);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/07 11:27:39");

  script_cve_id("CVE-2019-7164", "CVE-2019-7548");
  script_xref(name:"RHSA", value:"2019:0984");

  script_name(english:"RHEL 8 : python36:3.6 (RHSA-2019:0984)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for the python36:3.6 module is now available for Red Hat
Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Python is an interpreted, interactive, object-oriented programming
language, which includes modules, classes, exceptions, very high level
dynamic data types and dynamic typing. Python supports interfaces to
many system calls and libraries, as well as to various windowing
systems.

SQLAlchemy is an Object Relational Mapper (ORM) that provides a
flexible, high-level interface to SQL databases.

Security Fix(es) :

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
    value:"https://access.redhat.com/errata/RHSA-2019:0984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-7164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-7548"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-nose-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pymongo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-sqlalchemy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-virtualenv-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-bson-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-docutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-nose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pygments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pymongo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pymongo-gridfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-scipy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-sqlalchemy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-virtualenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python36-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python36-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python36-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:0984";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL8", reference:"python-nose-docs-1.3.7-30.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python-pymongo-doc-3.6.1-9.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python-sqlalchemy-doc-1.3.2-1.module+el8.0.0+2975+e0f02136")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python-virtualenv-doc-15.1.0-18.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python3-PyMySQL-0.8.0-10.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-bson-3.6.1-9.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-bson-3.6.1-9.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-bson-debuginfo-3.6.1-9.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-bson-debuginfo-3.6.1-9.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python3-docs-3.6.7-2.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python3-docutils-0.14-12.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python3-nose-1.3.7-30.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python3-pygments-2.2.0-20.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-pymongo-3.6.1-9.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-pymongo-3.6.1-9.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-pymongo-debuginfo-3.6.1-9.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-pymongo-debuginfo-3.6.1-9.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-pymongo-gridfs-3.6.1-9.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-pymongo-gridfs-3.6.1-9.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-scipy-1.0.0-19.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-scipy-1.0.0-19.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-scipy-debuginfo-1.0.0-19.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-scipy-debuginfo-1.0.0-19.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-sqlalchemy-1.3.2-1.module+el8.0.0+2975+e0f02136")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-sqlalchemy-1.3.2-1.module+el8.0.0+2975+e0f02136")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python3-virtualenv-15.1.0-18.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python3-wheel-0.30.0-13.module+el8.0.0+2966+d39a1df3")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python36-3.6.8-2.module+el8.0.0+2975+e0f02136")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python36-3.6.8-2.module+el8.0.0+2975+e0f02136")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python36-debug-3.6.8-2.module+el8.0.0+2975+e0f02136")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python36-debug-3.6.8-2.module+el8.0.0+2975+e0f02136")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python36-devel-3.6.8-2.module+el8.0.0+2975+e0f02136")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python36-devel-3.6.8-2.module+el8.0.0+2975+e0f02136")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python36-rpm-macros-3.6.8-2.module+el8.0.0+2975+e0f02136")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-nose-docs / python-pymongo-doc / python-sqlalchemy-doc / etc");
  }
}
