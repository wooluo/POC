#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:2411 and 
# Oracle Linux Security Advisory ELSA-2019-2411 respectively.
#

include("compat.inc");

if (description)
{
  script_id(127978);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/20 11:58:10");

  script_cve_id("CVE-2019-1125", "CVE-2019-13272");
  script_xref(name:"RHSA", value:"2019:2411");

  script_name(english:"Oracle Linux 8 : kernel (ELSA-2019-2411)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2019:2411 :

An update for kernel is now available for Red Hat Enterprise Linux 8.

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
    value:"https://oss.oracle.com/pipermail/el-errata/2019-August/009074.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/17");
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
  cve_list = make_list("CVE-2019-1125", "CVE-2019-13272");  
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for ELSA-2019-2411");
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
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"bpftool-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-abi-whitelists-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-abi-whitelists-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-core-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-core-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-cross-headers-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-cross-headers-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-debug-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-debug-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-debug-core-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-debug-core-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-debug-devel-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-debug-devel-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-debug-modules-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-debug-modules-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-debug-modules-extra-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-debug-modules-extra-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-devel-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-devel-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-doc-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-doc-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-headers-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-headers-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-modules-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-modules-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-modules-extra-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-modules-extra-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-tools-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-tools-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-tools-libs-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-tools-libs-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_exists(release:"EL8", rpm:"kernel-tools-libs-devel-4.18.0") && rpm_check(release:"EL8", cpu:"x86_64", reference:"kernel-tools-libs-devel-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"perf-4.18.0-80.7.2.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python3-perf-4.18.0-80.7.2.el8_0")) flag++;


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
