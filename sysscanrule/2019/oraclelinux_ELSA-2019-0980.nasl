#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:0980 and 
# Oracle Linux Security Advisory ELSA-2019-0980 respectively.
#

include("compat.inc");

if (description)
{
  script_id(127570);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-0211", "CVE-2019-0215");
  script_xref(name:"RHSA", value:"2019:0980");

  script_name(english:"Oracle Linux 8 : httpd:2.4 (ELSA-2019-0980)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2019:0980 :

An update for the httpd:2.4 module is now available for Red Hat
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
    value:"https://oss.oracle.com/pipermail/el-errata/2019-August/008960.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd:2.4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_http2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/08");
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
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"httpd-2.4.37-11.0.1.module+el8.0.0+5209+a98d70d6")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"httpd-devel-2.4.37-11.0.1.module+el8.0.0+5209+a98d70d6")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"httpd-filesystem-2.4.37-11.0.1.module+el8.0.0+5209+a98d70d6")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"httpd-manual-2.4.37-11.0.1.module+el8.0.0+5209+a98d70d6")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"httpd-tools-2.4.37-11.0.1.module+el8.0.0+5209+a98d70d6")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"mod_http2-1.11.3-2.module+el8.0.0+5209+a98d70d6")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"mod_ldap-2.4.37-11.0.1.module+el8.0.0+5209+a98d70d6")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"mod_md-2.4.37-11.0.1.module+el8.0.0+5209+a98d70d6")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"mod_proxy_html-2.4.37-11.0.1.module+el8.0.0+5209+a98d70d6")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"mod_session-2.4.37-11.0.1.module+el8.0.0+5209+a98d70d6")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"mod_ssl-2.4.37-11.0.1.module+el8.0.0+5209+a98d70d6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-filesystem / httpd-manual / httpd-tools / etc");
}
