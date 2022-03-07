#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126425);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/02 12:46:52");

  script_cve_id(
    "CVE-2019-3840"
  );

  script_name(english:"EulerOS 2.0 SP5 : libvirt (EulerOS-SA-2019-1684)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the libvirt packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerability :

  - A NULL pointer dereference flaw was discovered in
    libvirt in the way it gets interface information
    through the QEMU agent. An attacker in a guest VM can
    use this flaw to crash libvirtd and cause a denial of
    service.(CVE-2019-3840)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1684
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected libvirt package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["libvirt-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-client-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-config-network-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-config-nwfilter-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-driver-interface-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-driver-lxc-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-driver-network-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-driver-nodedev-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-driver-nwfilter-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-driver-qemu-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-driver-secret-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-driver-storage-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-driver-storage-core-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-driver-storage-disk-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-driver-storage-gluster-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-driver-storage-iscsi-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-driver-storage-logical-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-driver-storage-mpath-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-driver-storage-rbd-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-driver-storage-scsi-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-daemon-kvm-3.9.0-14.7.h2.eulerosv2r7",
        "libvirt-libs-3.9.0-14.7.h2.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt");
}
