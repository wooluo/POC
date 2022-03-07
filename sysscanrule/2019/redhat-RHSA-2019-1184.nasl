#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1184. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125050);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/24 15:26:42");

  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091");
  script_xref(name:"RHSA", value:"2019:1184");
  script_xref(name:"IAVA", value:"2019-A-0166");

  script_name(english:"RHEL 7 : libvirt (RHSA-2019:1184) (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for libvirt is now available for Red Hat Enterprise Linux
7.4 Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The libvirt library contains a C API for managing and interacting with
the virtualization capabilities of Linux and other operating systems.
In addition, libvirt provides tools for remote management of
virtualized systems.

Security Fix(es) :

* A flaw was found in the implementation of the 'fill buffer', a
mechanism used by modern CPUs when a cache-miss is made on L1 CPU
cache. If an attacker can generate a load operation that would create
a page fault, the execution will continue speculatively with incorrect
data from the fill buffer while the data is fetched from higher level
caches. This response time can be measured to infer data in the fill
buffer. (CVE-2018-12130)

* Modern Intel microprocessors implement hardware-level
micro-optimizations to improve the performance of writing data back to
CPU caches. The write operation is split into STA (STore Address) and
STD (STore Data) sub-operations. These sub-operations allow the
processor to hand-off address generation logic into these
sub-operations for optimized writes. Both of these sub-operations
write to a shared distributed processor structure called the
'processor store buffer'. As a result, an unprivileged attacker could
use this flaw to read private data resident within the CPU's processor
store buffer. (CVE-2018-12126)

* Microprocessors use a 'load port' subcomponent to perform load
operations from memory or IO. During a load operation, the load port
receives data from the memory or IO subsystem and then provides the
data to the CPU registers and operations in the CPU's pipelines.
Stale load operations results are stored in the 'load port' table
until overwritten by newer operations. Certain load-port operations
triggered by an attacker can be used to reveal data about previous
stale requests leaking data back to the attacker via a timing
side-channel. (CVE-2018-12127)

* Uncacheable memory on some microprocessors utilizing speculative
execution may allow an authenticated user to potentially enable
information disclosure via a side channel with local access.
(CVE-2019-11091)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/vulnerabilities/mds"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:1184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-12126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-12127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-12130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-11091"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ereg(pattern:"^7\.4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.4", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:1184";
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
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-admin-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-admin-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", reference:"libvirt-client-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-daemon-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-daemon-config-network-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-config-network-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-daemon-config-nwfilter-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-daemon-driver-interface-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-daemon-driver-lxc-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-daemon-driver-network-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-driver-network-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-daemon-driver-nodedev-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-daemon-driver-nwfilter-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-daemon-driver-secret-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-daemon-driver-storage-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-daemon-driver-storage-core-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-core-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-daemon-driver-storage-disk-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-disk-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-gluster-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-daemon-driver-storage-iscsi-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-iscsi-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-daemon-driver-storage-logical-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-logical-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-daemon-driver-storage-mpath-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-mpath-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-daemon-driver-storage-scsi-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-scsi-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-kvm-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-daemon-lxc-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-daemon-lxc-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", reference:"libvirt-debuginfo-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", reference:"libvirt-devel-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-docs-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-docs-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", reference:"libvirt-libs-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-lock-sanlock-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"libvirt-login-shell-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"libvirt-login-shell-3.2.0-14.el7_4.13")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", reference:"libvirt-nss-3.2.0-14.el7_4.13")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-admin / libvirt-client / libvirt-daemon / etc");
  }
}
