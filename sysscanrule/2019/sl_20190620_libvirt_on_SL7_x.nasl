#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(126091);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:39");

  script_cve_id("CVE-2019-10161", "CVE-2019-10166", "CVE-2019-10167", "CVE-2019-10168");

  script_name(english:"Scientific Linux Security Update : libvirt on SL7.x x86_64");
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

  - libvirt: arbitrary file read/exec via
    virDomainSaveImageGetXMLDesc API (CVE-2019-10161)

  - libvirt: virDomainManagedSaveDefineXML API exposed to
    readonly clients (CVE-2019-10166)

  - libvirt: arbitrary command execution via
    virConnectGetDomainCapabilities API (CVE-2019-10167)

  - libvirt: arbitrary command execution via
    virConnectBaselineHypervisorCPU and
    virConnectCompareHypervisorCPU APIs (CVE-2019-10168)

Bug Fix(es) :

  - Live migration fail with unsafe error when GPFS is used
    as shared filesystem"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1906&L=SCIENTIFIC-LINUX-ERRATA&P=8633
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/21");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-admin-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-bash-completion-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-client-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-config-network-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-network-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-core-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-disk-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-gluster-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-iscsi-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-logical-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-mpath-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-scsi-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-kvm-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-lxc-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-debuginfo-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-devel-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-docs-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-libs-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-lock-sanlock-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-login-shell-4.5.0-10.el7_6.12")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-nss-4.5.0-10.el7_6.12")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");