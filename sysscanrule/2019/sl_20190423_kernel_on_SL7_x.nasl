#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(124290);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/30 14:30:16");

  script_cve_id("CVE-2019-6974", "CVE-2019-7221");

  script_name(english:"Scientific Linux Security Update : kernel on SL7.x x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security Fix(es) :

  - Kernel: KVM: potential use-after-free via
    kvm_ioctl_create_device() (CVE-2019-6974)

  - Kernel: KVM: nVMX: use-after-free of the hrtimer for
    emulation of the preemption timer (CVE-2019-7221)

Bug Fix(es) :

  - rbd: avoid corruption on partially completed bios
    [rhel-7.6.z]

  - xfs_vm_writepages deadly embrace between kworker and
    user task. [rhel-7.6.z]

  - Offload Connections always get vlan priority 0
    [rhel-7.6.z]

  - [NOKIA] SL sends flood of Neighbour Solicitations under
    specific conditions [rhel-7.6.z]

  - SL 7.6 - Host crash occurred on NVMe/IB system while
    running controller reset [rhel-7.6.z]

  - [rhel7] raid0 md workqueue deadlock with stacked md
    devices [rhel-7.6.z]

  - [PureStorage7.6]nvme disconnect following an
    unsuccessful Admin queue creation causes kernel panic
    [rhel-7.6.z]

  - RFC: Regression with -fstack-check in 'backport upstream
    large stack guard patch to SL6' patch [rhel-7.6.z]

  - [Hyper-V] [SL 7.6]hv_netvsc: Fix a network regression
    after ifdown/ifup [rhel-7.6.z]

  - rtc_cmos: probe of 00:01 failed with error -16
    [rhel-7.6.z]

  - ACPI WDAT watchdog update [rhel-7.6.z]

  - high ovs-vswitchd CPU usage when VRRP over VXLAN tunnel
    causing qrouter fail-over [rhel-7.6.z]

  - Openshift node drops outgoing POD traffic due to NAT
    hashtable race in __ip_conntrack_confirm() [rhel-7.6.z]

  - [Backport] [v3,2/2] net: igmp: Allow user-space
    configuration of igmp unsolicited report interval
    [rhel-7.6.z]

  - [SL7.6]: Intermittently seen FIFO parity error on
    T6225-SO adapter [rhel-7.6.z]

  - The number of unsolict report about IGMP is incorrect
    [rhel-7.6.z]

  - RDT driver causing failure to boot on AMD Rome system
    with more than 255 CPUs [rhel-7.6.z]

  - mpt3sas_cm0: fault_state(0x2100)! [rhel-7.6.z]

  - rwsem in inconsistent state leading system to hung
    [rhel-7.6.z]"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1904&L=SCIENTIFIC-LINUX-ERRATA&P=6935
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bpftool-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-abi-whitelists-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-doc-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-3.10.0-957.12.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-957.12.1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
