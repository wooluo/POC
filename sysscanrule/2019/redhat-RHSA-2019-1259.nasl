#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1259. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125347);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/23  9:38:05");

  script_cve_id("CVE-2019-0757", "CVE-2019-0820", "CVE-2019-0980", "CVE-2019-0981");
  script_xref(name:"RHSA", value:"2019:1259");

  script_name(english:"RHEL 8 : dotnet (RHSA-2019:1259)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for dotnet is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

.NET Core is a managed-software framework. It implements a subset of
the .NET framework APIs and several new APIs, and it includes a CLR
implementation.

A new version of .NET Core that address security vulnerabilities is
now available. The updated version is .NET Core Runtime 2.1.11 and SDK
2.1.507.

Security Fix(es) :

* dotnet: NuGet Tampering Vulnerability (CVE-2019-0757)

* dotnet: timeouts for regular expressions are not enforced
(CVE-2019-0820)

* dotnet: infinite loop in URI.TryCreate leading to ASP.Net Core
Denial of Service (CVE-2019-0980)

* dotnet: crash in IPAddress.TryCreate leading to ASP.Net Core Denial
of Service (CVE-2019-0981)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* dotnet: new
SocketException((int)SocketError.InvalidArgument).Message is empty
(BZ#1712471)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/dotnet/core/blob/master/release-notes/2.1/2.1.11/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:1259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-0757"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-host-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-host-fxr-2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-host-fxr-2.1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-runtime-2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-runtime-2.1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-sdk-2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-sdk-2.1.5xx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dotnet-sdk-2.1.5xx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/23");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:1259";
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
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dotnet-2.1.507-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dotnet-debuginfo-2.1.507-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dotnet-debugsource-2.1.507-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dotnet-host-2.1.11-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dotnet-host-debuginfo-2.1.11-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dotnet-host-fxr-2.1-2.1.11-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dotnet-host-fxr-2.1-debuginfo-2.1.11-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dotnet-runtime-2.1-2.1.11-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dotnet-runtime-2.1-debuginfo-2.1.11-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dotnet-sdk-2.1-2.1.507-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dotnet-sdk-2.1.5xx-2.1.507-2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dotnet-sdk-2.1.5xx-debuginfo-2.1.507-2.el8_0")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dotnet / dotnet-debuginfo / dotnet-debugsource / dotnet-host / etc");
  }
}
