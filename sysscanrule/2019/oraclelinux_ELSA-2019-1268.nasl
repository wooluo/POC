#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:1268 and 
# Oracle Linux Security Advisory ELSA-2019-1268 respectively.
#

include("compat.inc");

if (description)
{
  script_id(127586);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-10132");
  script_xref(name:"RHSA", value:"2019:1268");

  script_name(english:"Oracle Linux 8 : virt:rhel (ELSA-2019-1268)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2019:1268 :

An update for the virt:rhel module is now available for Red Hat
Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Kernel-based Virtual Machine (KVM) offers a full virtualization
solution for Linux on numerous hardware platforms. The virt:rhel
module contains packages which provide user-space components used to
run virtual machines using KVM. The packages also provide APIs for
managing and interacting with the virtualized systems.

Security Fix(es) :

* libvirt: wrong permissions in systemd admin-sock due to missing
SocketMode parameter (CVE-2019-10132)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-August/008977.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virt:rhel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


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

flag = 0;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-admin-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-bash-completion-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-client-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-config-network-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-network-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-core-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-disk-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-gluster-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-iscsi-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-logical-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-mpath-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-scsi-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-daemon-kvm-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-devel-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-docs-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-libs-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-lock-sanlock-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"libvirt-nss-4.5.0-23.2.0.1.module+el8.0.0+5225+ce2eb65e")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-admin / libvirt-bash-completion / libvirt-client / etc");
}
