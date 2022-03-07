#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1131. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124752);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/10 10:59:32");

  script_cve_id("CVE-2019-11234", "CVE-2019-11235");
  script_xref(name:"RHSA", value:"2019:1131");

  script_name(english:"RHEL 7 : freeradius (RHSA-2019:1131)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for freeradius is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

FreeRADIUS is a high-performance and highly configurable free Remote
Authentication Dial In User Service (RADIUS) server, designed to allow
centralized authentication and authorization for a network.

Security Fix(es) :

* freeradius: eap-pwd: authentication bypass via an invalid curve
attack (CVE-2019-11235)

* freeradius: eap-pwd: fake authentication using reflection
(CVE-2019-11234)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:1131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-11234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-11235"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/10");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:1131";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"freeradius-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"freeradius-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"freeradius-debuginfo-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"freeradius-devel-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"freeradius-doc-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"freeradius-doc-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"freeradius-krb5-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"freeradius-krb5-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"freeradius-ldap-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"freeradius-ldap-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"freeradius-mysql-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"freeradius-mysql-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"freeradius-perl-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"freeradius-perl-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"freeradius-postgresql-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"freeradius-postgresql-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"freeradius-python-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"freeradius-python-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"freeradius-sqlite-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"freeradius-sqlite-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"freeradius-unixODBC-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"freeradius-unixODBC-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"freeradius-utils-3.0.13-10.el7_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"freeradius-utils-3.0.13-10.el7_6")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius / freeradius-debuginfo / freeradius-devel / etc");
  }
}
