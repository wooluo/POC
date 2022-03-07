#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1236. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125322);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/22 10:34:57");

  script_cve_id("CVE-2019-0820", "CVE-2019-0980", "CVE-2019-0981");
  script_xref(name:"RHSA", value:"2019:1236");

  script_name(english:"RHEL 7 : dotNET (RHSA-2019:1236)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updates for rh-dotnetcore10-dotnetcore, rh-dotnetcore11-dotnetcore,
rh-dotnet21-dotnet, rh-dotnet22-dotnet and rh-dotnet22-curl are now
available for .NET Core on Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

.NET Core is a managed-software framework. It implements a subset of
the .NET framework APIs and several new APIs, and it includes a CLR
implementation.

New versions of .NET Core that address security vulnerabilities are
now available. The updated versions are .NET Core 1.0.16, 1.1.13,
2.1.11, and 2.2.5.

Security Fix(es) :

* dotNET: timeouts for regular expressions are not enforced
(CVE-2019-0820)

* dotNET: infinite loop in URI.TryCreate leading to ASP.Net Core
Denial of Service (CVE-2019-0980)

* dotNET: crash in IPAddress.TryCreate leading to ASP.Net Core Denial
of Service (CVE-2019-0981)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* Re-enable bash completion in rh-dotnet22-dotnet (BZ#1654863)

* Error rebuilding rh-dotnet22-curl in CentOS (BZ#1678932)

* Broken apphost caused by unset DOTNET_ROOT (BZ#1703479)

* Make bash completion compatible with rh-dotnet22 packages
(BZ#1705259)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:1236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-0820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-0980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-0981"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet21-dotnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet21-dotnet-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet21-dotnet-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet21-dotnet-runtime-2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet21-dotnet-sdk-2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet21-dotnet-sdk-2.1.5xx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet21-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet22-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet22-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet22-dotnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet22-dotnet-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet22-dotnet-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet22-dotnet-host-fxr-2.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet22-dotnet-runtime-2.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet22-dotnet-sdk-2.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet22-dotnet-sdk-2.2.1xx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet22-libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet22-libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnet22-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnetcore10-dotnetcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnetcore10-dotnetcore-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnetcore11-dotnetcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-dotnetcore11-dotnetcore-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/22");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:1236";
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet21-2.1-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet21-dotnet-2.1.507-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet21-dotnet-debuginfo-2.1.507-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet21-dotnet-host-2.1.11-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet21-dotnet-runtime-2.1-2.1.11-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet21-dotnet-sdk-2.1-2.1.507-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet21-dotnet-sdk-2.1.5xx-2.1.507-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet21-runtime-2.1-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet22-2.2-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet22-curl-7.61.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet22-curl-debuginfo-7.61.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet22-dotnet-2.2.107-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet22-dotnet-debuginfo-2.2.107-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet22-dotnet-host-2.2.5-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet22-dotnet-host-fxr-2.2-2.2.5-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet22-dotnet-runtime-2.2-2.2.5-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet22-dotnet-sdk-2.2-2.2.107-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet22-dotnet-sdk-2.2.1xx-2.2.107-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet22-libcurl-7.61.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet22-libcurl-devel-7.61.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnet22-runtime-2.2-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnetcore10-dotnetcore-1.0.16-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnetcore10-dotnetcore-debuginfo-1.0.16-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnetcore11-dotnetcore-1.1.13-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rh-dotnetcore11-dotnetcore-debuginfo-1.1.13-1.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rh-dotnet21 / rh-dotnet21-dotnet / rh-dotnet21-dotnet-debuginfo / etc");
  }
}
