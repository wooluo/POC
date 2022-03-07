#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1602. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126250);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/26 10:34:06");

  script_cve_id("CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479");
  script_xref(name:"RHSA", value:"2019:1602");

  script_name(english:"RHEL 7 : kernel-alt (RHSA-2019:1602) (SACK Panic) (SACK Slowness)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel-alt is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel-alt packages provide the Linux kernel version 4.x.

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

* Kernel: tcp: excessive resource consumption while processing SACK
blocks allows remote denial of service (CVE-2019-11478)

* kernel: tcp: excessive resource consumption for TCP connections with
low MSS allows remote denial of service (CVE-2019-11479)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/vulnerabilities/tcpsack"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:1602"
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
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/26");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2019:1602");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:1602";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-4.14.0-115.8.2.el7a")) flag++;
  if (rpm_check(release:"RHEL7", reference:"kernel-abi-whitelists-4.14.0-115.8.2.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debug-4.14.0-115.8.2.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debug-debuginfo-4.14.0-115.8.2.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debug-devel-4.14.0-115.8.2.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debuginfo-4.14.0-115.8.2.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-4.14.0-115.8.2.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-devel-4.14.0-115.8.2.el7a")) flag++;
  if (rpm_check(release:"RHEL7", reference:"kernel-doc-4.14.0-115.8.2.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-headers-4.14.0-115.8.2.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-kdump-4.14.0-115.8.2.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-kdump-debuginfo-4.14.0-115.8.2.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-kdump-devel-4.14.0-115.8.2.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"perf-4.14.0-115.8.2.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"perf-debuginfo-4.14.0-115.8.2.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-perf-4.14.0-115.8.2.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-perf-debuginfo-4.14.0-115.8.2.el7a")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
  }
}