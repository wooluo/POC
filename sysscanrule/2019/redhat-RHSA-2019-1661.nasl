#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1661. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126520);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/08 10:33:36");

  script_cve_id("CVE-2019-10136");
  script_xref(name:"RHSA", value:"2019:1661");

  script_name(english:"RHEL 6 : spacewalk-backend (RHSA-2019:1661)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for spacewalk-backend is now available for Red Hat Satellite
5.8.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

Spacewalk is an Open Source systems management solution that provides
system provisioning, configuration and patching capabilities.

Security Fix(es) :

* spacewalk: Insecure computation of authentication signatures during
user authentication (CVE-2019-10136)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:1661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-10136"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-app");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-cdn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-config-files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-config-files-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-config-files-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-iss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-iss-export");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-package-push-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-sql-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-sql-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-xml-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/08");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:1661";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_exists(rpm:"spacewalk-backend-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-2.5.3-177.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-app-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-app-2.5.3-177.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-applet-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-applet-2.5.3-177.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-cdn-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-cdn-2.5.3-177.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-config-files-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-config-files-2.5.3-177.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-config-files-common-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-config-files-common-2.5.3-177.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-config-files-tool-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-config-files-tool-2.5.3-177.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-iss-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-iss-2.5.3-177.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-iss-export-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-iss-export-2.5.3-177.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-libs-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-libs-2.5.3-177.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-package-push-server-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-package-push-server-2.5.3-177.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-server-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-server-2.5.3-177.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-sql-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-sql-2.5.3-177.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-sql-oracle-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-sql-oracle-2.5.3-177.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-sql-postgresql-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-sql-postgresql-2.5.3-177.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-tools-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-tools-2.5.3-177.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-xml-export-libs-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-xml-export-libs-2.5.3-177.el6sat")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-xmlrpc-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-xmlrpc-2.5.3-177.el6sat")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spacewalk-backend / spacewalk-backend-app / etc");
  }
}
