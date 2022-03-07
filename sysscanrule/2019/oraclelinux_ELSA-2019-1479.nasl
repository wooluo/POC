#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:1479 and 
# Oracle Linux Security Advisory ELSA-2019-1479 respectively.
#

include("compat.inc");

if (description)
{
  script_id(127590);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479", "CVE-2019-9213");
  script_xref(name:"RHSA", value:"2019:1479");

  script_name(english:"Oracle Linux 8 : kernel (ELSA-2019-1479) (SACK Panic) (SACK Slowness)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2019:1479 :

An update for kernel is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* An integer overflow flaw was found in the way the Linux kernel's
networking subsystem processed TCP Selective Acknowledgment (SACK)
segments. While processing SACK segments, the Linux kernel's socket
buffer (SKB) data structure becomes fragmented. Each fragment is about
TCP maximum segment size (MSS) bytes. To efficiently process SACK
blocks, the Linux kernel merges multiple fragmented SKBs into one,
potentially overflowing the variable holding the number of segments. A
remote attacker could use this flaw to crash the Linux kernel by
sending a crafted sequence of SACK segments on a TCP connection with
small value of TCP MSS, resulting in a denial of service (DoS).
(CVE-2019-11477)

* kernel: lack of check for mmap minimum address in expand_downwards
in mm/ mmap.c leads to NULL pointer dereferences exploit on non-SMAP
platforms (CVE-2019-9213)

* Kernel: tcp: excessive resource consumption while processing SACK
blocks allows remote denial of service (CVE-2019-11478)

* Kernel: tcp: excessive resource consumption for TCP connections with
low MSS allows remote denial of service (CVE-2019-11479)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* [HPE 8.0 Bug] nvme drive power button does not turn off drive
(BZ#1700288)

* RHEL8.0 - hw csum failure seen in dmesg and console (using
mlx5/mlx4/ Mellanox) (BZ#1700289)

* RHEL8.0 - vfio-ap: add subsystem to matrix device to avoid libudev
failures (kvm) (BZ#1700290)

* [FJ8.1 Bug]: Make Fujitsu Erratum 010001 patch work on A64FX v1r0
(BZ# 1700901)

* [FJ8.0 Bug]: Fujitsu A64FX processor errata - panic by unknown fault
(BZ# 1700902)

* RHEL 8.0 Snapshot 4 - nvme create-ns command hangs after creating 20
namespaces on Bolt (NVMe) (BZ#1701140)

* [Cavium/Marvell 8.0 qed] Fix qed_mcp_halt() and qed_mcp_resume()
(backporting bug) (BZ#1704184)

* [Intel 8.1 Bug] PBF: Base frequency display fix (BZ#1706739)

* [RHEL8]read/write operation not permitted to
/sys/kernel/debug/gcov/reset (BZ#1708100)

* RHEL8.0 - ISST-LTE:pVM:fleetwood:LPM:raylp85:After lpm seeing the
console logs on the the lpar at target side (BZ#1708102)

* RHEL8.0 - Backport support for software count cache flush Spectre v2
mitigation (BZ#1708112)

* [Regression] RHEL8.0 - System crashed with one stress-ng-mremap
stressor on Boston (kvm host) (BZ#1708617)

* [intel ice Rhel 8 RC1] ethtool -A ethx causes interfaces to go down
(BZ# 1709433)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-August/008979.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
  cve_list = make_list("CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479", "CVE-2019-9213");  
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for ELSA-2019-1479");
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
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bpftool-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-abi-whitelists-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-abi-whitelists-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-core-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-core-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-cross-headers-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-cross-headers-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-debug-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-debug-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-debug-core-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-debug-core-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-debug-devel-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-debug-devel-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-debug-modules-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-debug-modules-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-debug-modules-extra-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-debug-modules-extra-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-devel-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-devel-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-doc-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-doc-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-headers-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-headers-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-modules-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-modules-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-modules-extra-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-modules-extra-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-tools-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-tools-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-tools-libs-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-tools-libs-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-tools-libs-devel-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-tools-libs-devel-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"perf-4.18.0-80.4.2.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python3-perf-4.18.0-80.4.2.el8_0")) flag++;


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
