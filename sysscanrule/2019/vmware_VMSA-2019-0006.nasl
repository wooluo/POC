#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2019-0006. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(124192);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/19 10:37:08");

  script_cve_id("CVE-2019-5516", "CVE-2019-5517", "CVE-2019-5520");
  script_xref(name:"VMSA", value:"2019-0006");

  script_name(english:"VMSA-2019-0006 : VMware ESXi, Workstation and Fusion updates address multiple out-of-bounds read vulnerabilities");
  script_summary(english:"Checks esxupdate output for the patches");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote VMware ESXi host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. VMware ESXi, Workstation and Fusion vertex shader out-of-bounds read
   vulnerability

  VMware ESXi, Workstation and Fusion updates address an out-of-bounds
  vulnerability with the vertex shader functionality.  Exploitation of
  this issue requires an attacker to have access to a virtual machine
  with 3D graphics enabled.  Successful exploitation of this issue may
  lead to information disclosure or may allow attackers with normal
  user privileges to create a denial-of-service condition on their own
  VM.  The workaround for this issue involves disabling the
  3D-acceleration feature. This feature is not enabled by default on
  ESXi and is enabled by default on Workstation and Fusion.
  
  VMware would like to thank Piotr Bania of Cisco Talos for reporting
  this issue to us.
  
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the identifier CVE-2019-5516 to this issue.

b. VMware ESXi, Workstation and Fusion multiple shader translator
   out-of-bounds read vulnerabilities

  VMware ESXi, Workstation and Fusion contain multiple out-of-bounds
  read vulnerabilities in the shader translator. Exploitation of these
  issues requires an attacker to have access to a virtual machine with
  3D graphics enabled.  Successful exploitation of these issues may
  lead to information disclosure or may allow attackers with normal
  user privileges to create a denial-of-service condition on their own
  VM.  The workaround for these issues involves disabling the
  3D-acceleration feature.  This feature is not enabled by default on
  ESXi and is enabled by default on Workstation and Fusion.

  VMware would like to thank RanchoIce of Tencent Security ZhanluLab
  for reporting these issues to us.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the identifier CVE-2019-5517 to these issues.

c. VMware ESXi, Workstation and Fusion out-of-bounds read
   vulnerability

  VMware ESXi, Workstation and Fusion updates address an out-of-bounds
  read vulnerability.  Exploitation of this issue requires an attacker
  to have access to a virtual machine with 3D graphics enabled.
  Successful exploitation of this issue may lead to information
  disclosure. The workaround for this issue involves disabling the
  3D-acceleration feature. This feature is not enabled by default on
  ESXi and is enabled by default on Workstation and Fusion.

  VMware would like to thank instructor working with Trend Micro's
  Zero Day Initiative for reporting this issue to us.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the identifier CVE-2019-5520 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2019/000455.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"VMware ESX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/VMware/release", "Host/VMware/version");
  script_require_ports("Host/VMware/esxupdate", "Host/VMware/esxcli_software_vibs");

  exit(0);
}


include("audit.inc");
include("vmware_esx_packages.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/VMware/release")) audit(AUDIT_OS_NOT, "VMware ESX / ESXi");
if (
  !get_kb_item("Host/VMware/esxcli_software_vibs") &&
  !get_kb_item("Host/VMware/esxupdate")
) audit(AUDIT_PACKAGE_LIST_MISSING);


init_esx_check(date:"2019-04-11");
flag = 0;


if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-base:6.5.0-2.83.13004031")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-tboot:6.5.0-2.83.13004031")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsan:6.5.0-2.83.12559347")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsanhealth:6.5.0-2.83.12559353")) flag++;

if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-base:6.7.0-1.44.12986307")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-update:6.7.0-1.44.12986307")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsan:6.7.0-1.44.11399678")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsanhealth:6.7.0-1.44.11399680")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
