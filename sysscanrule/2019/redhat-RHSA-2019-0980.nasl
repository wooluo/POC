#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:0980. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124667);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/17  9:44:17");

  script_cve_id("CVE-2019-0211", "CVE-2019-0215");
  script_xref(name:"RHSA", value:"2019:0980");

  script_name(english:"RHEL 8 : httpd:2.4 (RHSA-2019:0980)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for the httpd:2.4 module is now available for Red Hat
Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The httpd packages provide the Apache HTTP Server, a powerful,
efficient, and extensible web server.

Security Fix(es) :

* httpd: privilege escalation from modules scripts (CVE-2019-0211)

* httpd: mod_ssl: access control bypass when using per-location client
certification authentication (CVE-2019-0215)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:0980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-0211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-0215"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_http2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_http2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_http2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_md-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_proxy_html-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_session-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/08");
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
  rhsa = "RHSA-2019:0980";
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
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"httpd-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"httpd-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"httpd-debuginfo-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"httpd-debuginfo-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"httpd-debugsource-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"httpd-debugsource-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"httpd-devel-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"httpd-devel-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", reference:"httpd-filesystem-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", reference:"httpd-manual-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"httpd-tools-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"httpd-tools-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"httpd-tools-debuginfo-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"httpd-tools-debuginfo-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mod_http2-1.11.3-2.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mod_http2-1.11.3-2.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mod_http2-debuginfo-1.11.3-2.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mod_http2-debuginfo-1.11.3-2.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mod_http2-debugsource-1.11.3-2.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mod_http2-debugsource-1.11.3-2.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mod_ldap-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mod_ldap-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mod_ldap-debuginfo-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mod_ldap-debuginfo-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mod_md-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mod_md-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mod_md-debuginfo-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mod_md-debuginfo-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mod_proxy_html-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mod_proxy_html-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mod_proxy_html-debuginfo-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mod_proxy_html-debuginfo-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mod_session-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mod_session-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mod_session-debuginfo-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mod_session-debuginfo-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mod_ssl-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mod_ssl-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mod_ssl-debuginfo-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mod_ssl-debuginfo-2.4.37-11.module+el8.0.0+2969+90015743")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-debuginfo / httpd-debugsource / httpd-devel / etc");
  }
}