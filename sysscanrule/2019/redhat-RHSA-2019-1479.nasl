#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1479. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125967);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/21 12:43:08");

  script_cve_id("CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479", "CVE-2019-9213");
  script_xref(name:"RHSA", value:"2019:1479");

  script_name(english:"RHEL 8 : kernel (RHSA-2019:1479) (SACK Panic) (SACK Slowness)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 8.

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
    value:"https://access.redhat.com/security/vulnerabilities/tcpsack"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:1479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-9213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-11477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-11478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-11479"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");
include("ksplice.inc");

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

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479", "CVE-2019-9213");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2019:1479");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:1479";
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
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bpftool-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bpftool-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"bpftool-debuginfo-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bpftool-debuginfo-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bpftool-debuginfo-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", reference:"kernel-abi-whitelists-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-core-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-core-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-cross-headers-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-cross-headers-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-core-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-core-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"kernel-debug-debuginfo-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-debuginfo-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-debuginfo-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-devel-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-devel-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-modules-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-modules-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-modules-extra-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-modules-extra-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"kernel-debuginfo-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debuginfo-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debuginfo-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"kernel-debuginfo-common-aarch64-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-devel-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-devel-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", reference:"kernel-doc-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-headers-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-headers-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-modules-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-modules-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-modules-extra-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-modules-extra-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-tools-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-tools-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"kernel-tools-debuginfo-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-tools-debuginfo-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-tools-debuginfo-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-tools-libs-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"kernel-tools-libs-devel-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-tools-libs-devel-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-core-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-debuginfo-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-devel-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-modules-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-modules-extra-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"perf-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"perf-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"perf-debuginfo-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"perf-debuginfo-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"perf-debuginfo-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-perf-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-perf-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"python3-perf-debuginfo-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-perf-debuginfo-4.18.0-80.4.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-perf-debuginfo-4.18.0-80.4.2.el8_0")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / bpftool-debuginfo / kernel / kernel-abi-whitelists / etc");
  }
}
