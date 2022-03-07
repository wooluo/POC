#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:0818 and 
# CentOS Errata and Security Advisory 2019:0818 respectively.
#

include("compat.inc");

if (description)
{
  script_id(124416);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/15 14:20:29");

  script_cve_id("CVE-2019-6974", "CVE-2019-7221");
  script_xref(name:"RHSA", value:"2019:0818");

  script_name(english:"CentOS 7 : kernel (CESA-2019:0818)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* Kernel: KVM: potential use-after-free via kvm_ioctl_create_device()
(CVE-2019-6974)

* Kernel: KVM: nVMX: use-after-free of the hrtimer for emulation of
the preemption timer (CVE-2019-7221)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* rbd: avoid corruption on partially completed bios [rhel-7.6.z]
(BZ#1672514)

* xfs_vm_writepages deadly embrace between kworker and user task.
[rhel-7.6.z] (BZ#1673281)

* Offload Connections always get vlan priority 0 [rhel-7.6.z]
(BZ#1673821)

* [NOKIA] RHEL sends flood of Neighbour Solicitations under specific
conditions [rhel-7.6.z] (BZ#1677179)

* RHEL 7.6 - Host crash occurred on NVMe/IB system while running
controller reset [rhel-7.6.z] (BZ#1678214)

* [rhel7] raid0 md workqueue deadlock with stacked md devices
[rhel-7.6.z] (BZ#1678215)

* [PureStorage7.6]nvme disconnect following an unsuccessful Admin
queue creation causes kernel panic [rhel-7.6.z] (BZ#1678216)

* RFC: Regression with -fstack-check in 'backport upstream large stack
guard patch to RHEL6' patch [rhel-7.6.z] (BZ#1678221)

* [Hyper-V] [RHEL 7.6]hv_netvsc: Fix a network regression after
ifdown/ifup [rhel-7.6.z] (BZ#1679997)

* rtc_cmos: probe of 00:01 failed with error -16 [rhel-7.6.z]
(BZ#1683078)

* ACPI WDAT watchdog update [rhel-7.6.z] (BZ#1683079)

* high ovs-vswitchd CPU usage when VRRP over VXLAN tunnel causing
qrouter fail-over [rhel-7.6.z] (BZ#1683093)

* Openshift node drops outgoing POD traffic due to NAT hashtable race
in __ip_conntrack_confirm() [rhel-7.6.z] (BZ#1686766)

* [Backport] [v3,2/2] net: igmp: Allow user-space configuration of
igmp unsolicited report interval [rhel-7.6.z] (BZ#1686771)

* [RHEL7.6]: Intermittently seen FIFO parity error on T6225-SO adapter
[rhel-7.6.z] (BZ#1687487)

* The number of unsolict report about IGMP is incorrect [rhel-7.6.z]
(BZ# 1688225)

* RDT driver causing failure to boot on AMD Rome system with more than
255 CPUs [rhel-7.6.z] (BZ#1689120)

* mpt3sas_cm0: fault_state(0x2100)! [rhel-7.6.z] (BZ#1689379)

* rwsem in inconsistent state leading system to hung [rhel-7.6.z] (BZ#
1690323)

Users of kernel are advised to upgrade to these updated packages,
which fix these bugs."
  );
  # https://lists.centos.org/pipermail/centos-announce/2019-April/023278.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bpftool-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-957.12.1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
