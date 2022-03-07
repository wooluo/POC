#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2019-2.0-0160. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(125396);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/30 11:03:54");

  script_cve_id("CVE-2019-11599", "CVE-2019-11810", "CVE-2019-11815");

  script_name(english:"Photon OS 2.0: Linux PHSA-2019-2.0-0160");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the linux package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Updates-2-160.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11815");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/PhotonOS/release");
if (isnull(release) || release !~ "^VMware Photon") audit(AUDIT_OS_NOT, "PhotonOS");
if (release !~ "^VMware Photon (?:Linux|OS) 2\.0(\D|$)") audit(AUDIT_OS_NOT, "PhotonOS 2.0");

if (!get_kb_item("Host/PhotonOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "PhotonOS", cpu);

flag = 0;

if (rpm_check(release:"PhotonOS-2.0", reference:"linux-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-api-headers-4.9.173-1.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-aws-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-aws-debuginfo-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-aws-devel-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-aws-docs-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-aws-drivers-gpu-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-aws-oprofile-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-aws-sound-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-aws-tools-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-debuginfo-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-devel-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-docs-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-drivers-gpu-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-esx-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-esx-debuginfo-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-esx-devel-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-esx-docs-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-oprofile-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-secure-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-secure-debuginfo-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-secure-devel-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-secure-docs-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-secure-lkcm-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-sound-4.9.173-2.ph2")) flag++;
if (rpm_check(release:"PhotonOS-2.0", reference:"linux-tools-4.9.173-2.ph2")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux");
}
