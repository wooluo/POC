#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2037. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127654);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-10153");
  script_xref(name:"RHSA", value:"2019:2037");

  script_name(english:"RHEL 7 : fence-agents (RHSA-2019:2037)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for fence-agents is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The fence-agents packages provide a collection of scripts for handling
remote power management for cluster devices. They allow failed or
unreachable nodes to be forcibly restarted and removed from the
cluster.

Security Fix(es) :

* fence-agents: mis-handling of non-ASCII characters in guest comment
fields (CVE-2019-10153)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section."
  );
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:2037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-10153"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-aliyun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-amt-ws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-apc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-apc-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-azure-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-bladecenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-brocade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-cisco-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-cisco-ucs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-drac5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-eaton-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-emerson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-eps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-heuristics-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-hpblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-ibmblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-ifmib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-ilo-moonshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-ilo-mp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-ilo-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-ilo2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-intelmodular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-ipdu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-ipmilan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-redfish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-rsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-rsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-sbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-virsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-vmware-rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-vmware-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-wti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fence-agents-zvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
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
  rhsa = "RHSA-2019:2037";
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-aliyun-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-all-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-all-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-amt-ws-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-amt-ws-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-apc-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-apc-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-apc-snmp-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-apc-snmp-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-aws-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-azure-arm-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-bladecenter-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-bladecenter-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-brocade-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-brocade-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-cisco-mds-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-cisco-mds-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-cisco-ucs-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-cisco-ucs-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-common-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-common-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-compute-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-compute-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-debuginfo-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-debuginfo-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-drac5-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-drac5-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-eaton-snmp-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-eaton-snmp-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-emerson-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-emerson-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-eps-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-eps-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-gce-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-heuristics-ping-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-heuristics-ping-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-hpblade-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-hpblade-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-ibmblade-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-ibmblade-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-ifmib-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-ifmib-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-ilo-moonshot-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-ilo-moonshot-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-ilo-mp-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-ilo-mp-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-ilo-ssh-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-ilo-ssh-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-ilo2-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-ilo2-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-intelmodular-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-intelmodular-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-ipdu-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-ipdu-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-ipmilan-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-ipmilan-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-kdump-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-kdump-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-mpath-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-mpath-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-redfish-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-redfish-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-rhevm-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-rhevm-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-rsa-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-rsa-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-rsb-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-rsb-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-sbd-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-sbd-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-scsi-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-scsi-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-virsh-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-virsh-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-vmware-rest-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-vmware-rest-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-vmware-soap-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-vmware-soap-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-wti-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fence-agents-wti-4.2.1-24.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"fence-agents-zvm-4.2.1-24.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fence-agents-aliyun / fence-agents-all / fence-agents-amt-ws / etc");
  }
}
