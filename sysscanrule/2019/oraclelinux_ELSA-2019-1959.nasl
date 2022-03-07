#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:1959 and 
# Oracle Linux Security Advisory ELSA-2019-1959 respectively.
#

include("compat.inc");

if (description)
{
  script_id(127976);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/20 11:58:10");

  script_cve_id("CVE-2018-20784", "CVE-2019-11085", "CVE-2019-11810", "CVE-2019-11811");
  script_xref(name:"RHSA", value:"2019:1959");

  script_name(english:"Oracle Linux 8 : kernel (ELSA-2019-1959)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2019:1959 :

An update for kernel is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* kernel: insufficient input validation in kernel mode driver in Intel
i915 graphics leads to privilege escalation (CVE-2019-11085)

* kernel: DMA attack using peripheral devices (Thunderclap)
(BZ#1690716)

* kernel: infinite loop in update_blocked_averages() in
kernel/sched/fair.c leading to denial of service (CVE-2018-20784)

* kernel: a NULL pointer dereference in drivers/scsi/megaraid/
megaraid_sas_base.c leading to DoS (CVE-2019-11810)

* kernel: use-after-free in drivers/char/ipmi/ipmi_si_intf.c,
ipmi_si_mem_io.c, ipmi_si_port_io.c (CVE-2019-11811)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* [DELL 8.0 z-stream BUG] - 'CPU unsupported' message with CFL-H/S 8+2
due to updated Stepping (BZ#1711048)

* RHEL8.0 Snapshot4 - [LTC Test] Guest crashes during vfio device
hot-plug/ un-plug operations. (kvm) (BZ#1714746)

* Using Transactional Memory (TM) in a Guest Locks-up Host Core on a
Power9 System (BZ#1714751)

* VRSAVE register not properly saved and restored (BZ#1714753)

* Fix potential spectre gadget in arch/s390/kvm/interrupt.c
(BZ#1714754)

* RHEL8.0 RC2 - kernel/KVM - count cache flush Spectre v2 mitigation
(required for POWER9 DD2.3) (BZ#1715018)

* iommu/amd: Set exclusion range correctly (BZ#1715336)

* RHEL8.0 - sched/fair: Do not re-read ->h_load_next during
hierarchical load calculation (BZ#1715337)

* cross compile builds are broken (BZ#1715339)

* Patch generated by 'make rh-test-patch' doesn't get applied during
build (BZ#1715340)

* hard lockup panic in during execution of CFS bandwidth period timer
(BZ# 1715345)

* perf annotate -P does not give full paths (BZ#1716887)

* [Dell EMC 8.0 BUG] File system corrupting with I/O Stress on H330
PERC on AMD Systems if IOMMU passthrough is disabled (BZ#1717344)

* Fix Spectre v1 gadgets in drivers/gpu/drm/drm_bufs.c and
drivers/gpu/drm/ drm_ioctl.c (BZ#1717382)

* BUG: SELinux doesn't handle NFS crossmnt well (BZ#1717777)

* krb5{,i,p} doesn't work with older enctypes on aarch64 (BZ#1717800)

* [RHEL-8.0][s390x]ltp-lite mtest06 testing hits EWD due to: rcu:
INFO: rcu_sched self-detected stall on CPU (BZ#1717801)

* RHEL 8 Snapshot-6: CN1200E SW iSCSI I/O performance degradation
after a SCSI device/target reset rhel-8.0.0.z] (BZ#1717804)

* dm cache metadata: Fix loading discard bitset (BZ#1717868)

* jit'd java code on power9 ppc64le experiences stack corruption
(BZ#1717869)

* BUG: connect(AF_UNSPEC, ...) on a connected socket returns an error
(BZ# 1717870)

* mm: BUG: unable to handle kernel paging request at 0000000057ac6e9d
(BZ# 1718237)

* [HPE 8.0 BUG] DCPMM fsdax boot initialization takes a long time
causing auto-mount to fail (BZ#1719635)

* AMD Rome: WARNING: CPU: 1 PID: 0 at
arch/x86/kernel/cpu/mcheck/mce.c:1510 mcheck_cpu_init+0x7a/0x460
(BZ#1721233)

* [RHEL8.1] AMD Rome: EDAC amd64: Error: F0 not found, device 0x1460
(broken BIOS?) (BZ#1722365)

* AMD Rome: Intermittent NMI received for unknown reason (BZ#1722367)

* [DELL 8.0 BUG] - 'CPU unsupported' message with WHL-U due to updated
Stepping (BZ#1722372)

Enhancement(s) :

* RHEL 8 - AMD Rome Support (BZ#1721972)

Users of kernel are advised to upgrade to these updated packages,
which fix these bugs and add this enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-August/009071.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");
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
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 8", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2018-20784", "CVE-2019-11085", "CVE-2019-11810", "CVE-2019-11811");  
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for ELSA-2019-1959");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

kernel_major_minor = get_kb_item("Host/uname/major_minor");
if (empty_or_null(kernel_major_minor)) exit(1, "Unable to determine kernel major-minor level.");
expected_kernel_major_minor = "4.18";
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, "running kernel level " + expected_kernel_major_minor + ", it is running kernel level " + kernel_major_minor);

flag = 0;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bpftool-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-abi-whitelists-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-abi-whitelists-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-core-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-core-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-cross-headers-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-cross-headers-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-debug-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-debug-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-debug-core-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-debug-core-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-debug-devel-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-debug-devel-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-debug-modules-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-debug-modules-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-debug-modules-extra-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-debug-modules-extra-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-devel-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-devel-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-doc-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-doc-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-headers-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-headers-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-modules-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-modules-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-modules-extra-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-modules-extra-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-tools-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-tools-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-tools-libs-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-tools-libs-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-tools-libs-devel-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-tools-libs-devel-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"perf-4.18.0-80.7.1.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python3-perf-4.18.0-80.7.1.el8_0")) flag++;


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
