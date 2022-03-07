#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:0458. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122738);
  script_version("1.4");
  script_cvs_date("Date: 2019/04/25  9:51:46");

  script_cve_id("CVE-2019-3831");
  script_xref(name:"RHSA", value:"2019:0458");

  script_name(english:"RHEL 7 : Virtualization Manager (RHSA-2019:0458)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for vdsm is now available for Red Hat Virtualization 4 for
Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The VDSM service is required by a Virtualization Manager to manage the
Linux hosts. VDSM manages and monitors the host's storage, memory and
networks as well as virtual machine creation, other host
administration tasks, statistics gathering, and log collection.

The following packages have been upgraded to a later upstream version:
vdsm (4.20.47). (BZ#1677458)

Security Fix(es) :

* vdsm: privilege escalation to root via systemd_run (CVE-2019-3831)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* VDSM attempted to collect OpenStack related information, even on
hosts that are not connected to OpenStack, and displayed a repeated
error message in the system log. In this release, errors originating
from OpenStack related information are not recorded in the system log.
As a result, the system log is quieter. (BZ#1673765)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:0458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-3831"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-checkips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-cpuflags");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-ethtool-options");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-extra-ipv4-addrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-fcoe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-localdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-macspoof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-nestedvt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-openstacknet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-vhostmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-vmfex-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-jsonrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-yajsonrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/11");
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
  rhsa = "RHSA-2019:0458";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"redhat-release-virtualization-host-4.2"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Red Hat Virtualization 4");

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vdsm-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-api-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-client-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-common-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vdsm-gluster-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vdsm-hook-checkips-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-hook-cpuflags-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-hook-ethtool-options-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vdsm-hook-extra-ipv4-addrs-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-hook-fcoe-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-hook-localdisk-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-hook-macspoof-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-hook-nestedvt-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-hook-openstacknet-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-hook-vhostmd-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-hook-vmfex-dev-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-http-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-jsonrpc-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vdsm-network-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-python-4.20.47-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vdsm-yajsonrpc-4.20.47-1.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vdsm / vdsm-api / vdsm-client / vdsm-common / vdsm-gluster / etc");
  }
}
