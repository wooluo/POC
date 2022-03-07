#
# (C) WebRAY Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2019-0038.
#

include("compat.inc");

if (description)
{
  script_id(127565);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2018-20169", "CVE-2019-1125", "CVE-2019-11833", "CVE-2019-12378", "CVE-2019-12381");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2019-0038)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - x86/speculation: Exclude ATOMs from speculation through
    SWAPGS (Thomas Gleixner) [Orabug: 29967571]
    (CVE-2019-1125)

  - x86/speculation: Enable Spectre v1 swapgs mitigations
    (Josh Poimboeuf) [Orabug: 29967571] (CVE-2019-1125)

  - x86/speculation: Prepare entry code for Spectre v1
    swapgs mitigations (Josh Poimboeuf) [Orabug: 29967571]
    (CVE-2019-1125)

  - mlx4_core: change log_num_[qp,rdmarc] with scale_profile
    (Mukesh Kacker) [Orabug: 30064080]

  - scsi: storvsc: Fix scsi_cmd error assignments in
    storvsc_handle_error (Cathy Avery) [Orabug: 30052805]

  - USB: check usb_get_extra_descriptor for proper size
    (Mathias Payer) [Orabug: 29755247] (CVE-2018-20169)

  - rds: ib: Fix dereference of conn when NULL and cleanup
    thereof (H&aring kon Bugge) [Orabug: 29924849]

  - ext4: zero out the unused memory region in the extent
    tree block (Sriram Rajagopalan) [Orabug: 29925523]
    (CVE-2019-11833) (CVE-2019-11833)

  - ip_sockglue: Fix missing-check bug in ip_ra_control (Gen
    Zhang) [Orabug: 29926005] (CVE-2019-12381)

  - ipv6_sockglue: Fix a missing-check bug in ip6_ra_control
    (Gen Zhang) [Orabug: 29926057] (CVE-2019-12378)

  - x86/microcode: fix x86_spec_ctrl_mask on late loading.
    (Mihai Carabas) [Orabug: 29941248]

  - net: rds: fix rds recv memory leak (Zhu Yanjun) [Orabug:
    30034815]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2019-August/000954.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.29.3.1.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.29.3.1.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
