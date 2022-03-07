#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2411. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127722);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/14 10:36:48");

  script_cve_id("CVE-2019-1125", "CVE-2019-13272");
  script_xref(name:"RHSA", value:"2019:2411");

  script_name(english:"RHEL 8 : kernel (RHSA-2019:2411)");
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

* kernel: broken permission and object lifetime handling for
PTRACE_TRACEME (CVE-2019-13272)

* kernel: hw: Spectre SWAPGS gadget vulnerability (CVE-2019-1125)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/4329821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:2411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-1125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-13272"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
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
  cve_list = make_list("CVE-2019-1125", "CVE-2019-13272");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2019:2411");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:2411";
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
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bpftool-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bpftool-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"bpftool-debuginfo-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"bpftool-debuginfo-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"bpftool-debuginfo-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", reference:"kernel-abi-whitelists-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-core-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-core-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-cross-headers-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-cross-headers-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-core-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-core-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"kernel-debug-debuginfo-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-debuginfo-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-debuginfo-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-devel-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-devel-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-modules-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-modules-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debug-modules-extra-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debug-modules-extra-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"kernel-debuginfo-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debuginfo-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debuginfo-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"kernel-debuginfo-common-aarch64-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-devel-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-devel-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", reference:"kernel-doc-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-headers-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-headers-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-modules-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-modules-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-modules-extra-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-modules-extra-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-tools-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-tools-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"kernel-tools-debuginfo-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-tools-debuginfo-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-tools-debuginfo-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-tools-libs-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"kernel-tools-libs-devel-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"kernel-tools-libs-devel-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-core-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-debuginfo-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-devel-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-modules-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"kernel-zfcpdump-modules-extra-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"perf-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"perf-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"perf-debuginfo-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"perf-debuginfo-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"perf-debuginfo-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-perf-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-perf-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"python3-perf-debuginfo-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-perf-debuginfo-4.18.0-80.7.2.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-perf-debuginfo-4.18.0-80.7.2.el8_0")) flag++;

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
