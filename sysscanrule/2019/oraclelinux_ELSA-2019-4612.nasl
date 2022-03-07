#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-4612.
#

include("compat.inc");

if (description)
{
  script_id(124048);
  script_version("1.4");
  script_cvs_date("Date: 2019/07/24  9:40:20");

  script_cve_id("CVE-2019-3701", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222", "CVE-2019-8912", "CVE-2019-8980", "CVE-2019-9213");

  script_name(english:"Oracle Linux 7 : Unbreakable Enterprise kernel (ELSA-2019-4612)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[4.14.35-1844.4.5.el7uek]
- x86/apic/x2apic: set back affinity of a single interrupt to one cpu (Mridula Shastry)  [Orabug: 29510342]

[4.14.35-1844.4.4.el7uek]
- ext4: fix data corruption caused by unaligned direct AIO (Lukas Czerner)  [Orabug: 29598590]
- swiotlb: checking whether swiotlb buffer is full with io_tlb_used (Dongli Zhang)  [Orabug: 29587097]
- swiotlb: add debugfs to track swiotlb buffer usage (Dongli Zhang)  [Orabug: 29587097]
- swiotlb: fix comment on swiotlb_bounce() (Dongli Zhang)  [Orabug: 29587097]
- scsi: target: add device product id and revision configfs attributes (Alan Adamson)  [Orabug: 29344881]
- scsi: target: remove hardcoded T10 Vendor ID in INQUIRY response (David Disseldorp)  [Orabug: 29344881]
- scsi: target: add device vendor_id configfs attribute (David Disseldorp)  [Orabug: 29344881]
- scsi: target: consistently null-terminate t10_wwn strings (David Disseldorp)  [Orabug: 29344881]
- scsi: target: use consistent left-aligned ASCII INQUIRY data (David Disseldorp)  [Orabug: 29344881]
- x86/speculation: Keep enhanced IBRS on when prctl is used for SSBD control (Alejandro Jimenez)  [Orabug: 29526400]
- drm/amdkfd: fix amdkfd use-after-free GP fault (Randy Dunlap)  [Orabug: 29534199]

[4.14.35-1844.4.3.el7uek]
- can: gw: ensure DLC boundaries after CAN frame modification (Oliver Hartkopp)  [Orabug: 29215297]  {CVE-2019-3701} {CVE-2019-3701}

[4.14.35-1844.4.2.el7uek]
- x86/speculation: Clean up enhanced IBRS checks in bugs.c (Alejandro Jimenez)  [Orabug: 29423796]
- x86/speculation: Keep enhanced IBRS on when spec_store_bypass_disable=on is used (Alejandro Jimenez)  [Orabug: 29423796]
- kvm/speculation: Allow KVM guests to use SSBD even if host does not (Alejandro Jimenez)  [Orabug: 29423796]
- exec: Fix mem leak in kernel_read_file (YueHaibing)  [Orabug: 29454858]  {CVE-2019-8980}
- net: crypto set sk to NULL when af_alg_release. (Mao Wenan)  [Orabug: 29454874]  {CVE-2019-8912}
- {net, IB}/mlx5: Raise fatal IB event when sys error occurs (Daniel Jurgens)  [Orabug: 29479744]
- net/mlx5e: Avoid query PPCNT register if not supported by the device (Eyal Davidovich)  [Orabug: 29479795]
- mm: enforce min addr even if capable() in expand_downwards() (Jann Horn)  [Orabug: 29501977]  {CVE-2019-9213}
- [UEK-5] IB/mlx5_core: Use kzalloc when allocating PD (Erez Alfasi)  [Orabug: 29479806]
- IB/mlx5: Change debugfs to have per port contents (Parav Pandit)  [Orabug: 29486784]
- Revert 'IB/mlx5: Change debugfs to have per port contents' (Qing Huang)  [Orabug: 29486784]
- scsi: scsi_transport_iscsi: modify detected conn err to KERN_ERR (Fred Herard)  [Orabug: 29487789]
- xen/blkfront: avoid NULL blkfront_info dereference on device removal (Vasilis Liaskovitis)  [Orabug: 29489795]
- qlcnic: fix Tx descriptor corruption on 82xx devices (Shahed Shaikh)  [Orabug: 29495427]

[4.14.35-1844.4.1.el7uek]
- scsi: libiscsi: Fix race between iscsi_xmit_task and iscsi_complete_task (Anoob Soman)  [Orabug: 29024514]
- scsi: scsi_transport_iscsi: redirect conn error to console (Fred Herard)  [Orabug: 29469713]
- Revert x86/apic/x2apic: set affinity of a single interrupt to one cpu (Mridula Shastry)  [Orabug: 29469651]
- net/mlx5: Fix error handling in load one (Maor Gottlieb)  [Orabug: 29019396]
- net/mlx5: Fix mlx5_get_uars_page to return error code (Eran Ben Elisha)  [Orabug: 29019396]
- net/mlx5: Fix memory leak in bad flow of mlx5_alloc_irq_vectors (Alaa Hleihel)  [Orabug: 29019396]
- net/mlx4_core: Fix wrong calculation of free counters (Eran Ben Elisha)  [Orabug: 29019396]
- net/mlx5: Free IRQs in shutdown path (Daniel Jurgens)  [Orabug: 29019427]
- net/mlx5e: DCBNL fix min inline header size for dscp (Huy Nguyen)  [Orabug: 29019427]
- IB/mlx4: Fix integer overflow when calculating optimal MTT size (Jack Morgenstein)  [Orabug: 29019427]
- net/mlx5: Fix mlx5_get_vector_affinity function (Israel Rukshin)  [Orabug: 29019427]
- net/mlx5e: Fixed sleeping inside atomic context (Aviad Yehezkel)  [Orabug: 29019427]
- IB/core: Generate GID change event regardless of RoCE GID table property (Parav Pandit)  [Orabug: 29019427]
- net/mlx5: Vport, Use 'kvfree()' for memory allocated by 'kvzalloc()' (Christophe JAILLET)  [Orabug: 29019430]
- IB/mlx4: Use 4K pages for kernel QP's WQE buffer (Jack Morgenstein)  [Orabug: 29019795]
- net/mlx5: Add missing SET_DRIVER_VERSION command translation (Noa Osherovich)  [Orabug: 29447325]
- net/mlx5: E-Switch, Fix memory leak when creating switchdev mode FDB tables (Raed Salem)  [Orabug: 29447325]
- net/mlx5: Fix debugfs cleanup in the device init/remove flow (Jack Morgenstein)  [Orabug: 29447325]
- net/mlx5: Check for error in mlx5_attach_interface (Huy Nguyen)  [Orabug: 29447325]
- net/mlx5: Fix use-after-free in self-healing flow (Jack Morgenstein)  [Orabug: 29447325]
- uek-rpm: update list of removed files, generated by depmod on install stage (Alexander Burmashev)  [Orabug: 29460369]

[4.14.35-1844.4.0.el7uek]
- fs/dcache.c: add cond_resched() in shrink_dentry_list() (Nikolay Borisov)  [Orabug: 29450975]
- net_failover: delay taking over primary device to accommodate udevd renaming (Si-Wei Liu)
- hugetlbfs: fix races and page leaks during migration (Mike Kravetz)  [Orabug: 29443877]
- rds: update correct congestion map for loopback transport (Mukesh Kacker)  [Orabug: 29431289]
- KVM: nVMX: unconditionally cancel preemption timer in free_nested (CVE-2019-7221) (Peter Shier)  [Orabug: 29408638]  {CVE-2019-7221}
- KVM: x86: work around leak of uninitialized stack contents (CVE-2019-7222) (Paolo Bonzini)  [Orabug: 29408618]  {CVE-2019-7222}
- kvm: fix kvm_ioctl_create_device() reference counting (CVE-2019-6974) (Jann Horn)  [Orabug: 29408541]  {CVE-2019-6974}
- ib_core: initialize shpd field when allocating 'struct ib_pd' (Mukesh Kacker)  [Orabug: 29384900]
- bnxt_en: Return linux standard errors in bnxt_ethtool.c (Vasundhara Volam)  [Orabug: 29261957]
- bnxt_en: Don't set ETS on unused TCs. (Michael Chan)  [Orabug: 29261957]
- bnxt_en: get the reduced max_irqs by the ones used by RDMA (Vasundhara Volam)  [Orabug: 29261957]
- bnxt_en: free hwrm resources, if driver probe fails. (Venkat Duvvuru)  [Orabug: 29261957]
- bnxt_en: Fix enables field in HWRM_QUEUE_COS2BW_CFG request (Vasundhara Volam)  [Orabug: 29261957]
- bnxt_en: Fix VNIC reservations on the PF. (Michael Chan)  [Orabug: 29261957]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-April/008648.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");
include("ksplice.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-3701", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222", "CVE-2019-8912", "CVE-2019-8980", "CVE-2019-9213");  
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for ELSA-2019-4612");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

kernel_major_minor = get_kb_item("Host/uname/major_minor");
if (empty_or_null(kernel_major_minor)) exit(1, "Unable to determine kernel major-minor level.");
expected_kernel_major_minor = "4.14";
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, "running kernel level " + expected_kernel_major_minor + ", it is running kernel level " + kernel_major_minor);

flag = 0;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-4.14.35-1844.4.5.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-4.14.35-1844.4.5.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-devel-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.14.35-1844.4.5.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-devel-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-devel-4.14.35-1844.4.5.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-doc-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-doc-4.14.35-1844.4.5.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-tools-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-tools-4.14.35-1844.4.5.el7uek")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
