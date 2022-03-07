#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2019-0005. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(123556);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/05 15:17:20");

  script_cve_id("CVE-2019-5514", "CVE-2019-5515", "CVE-2019-5518", "CVE-2019-5519", "CVE-2019-5524");
  script_xref(name:"VMSA", value:"2019-0005");
  script_xref(name:"IAVA", value:"2019-A-0099");

  script_name(english:"VMSA-2019-0005 : VMware ESXi, Workstation and Fusion updates address multiple security issues");
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
"a. VMware ESXi, Workstation and Fusion UHCI out-of-bounds read/write
and TOCTOU vulnerabilities

VMware ESXi, Workstation and Fusion contain an out-of-bounds read/write
vulnerability and a Time-of-check Time-of-use (TOCTOU) vulnerability in
the virtual USB 1.1 UHCI (Universal Host Controller Interface).
Exploitation of these issues requires an attacker to have access to a
virtual machine with a virtual USB controller present. These issues may
allow a guest to execute code on the host.

VMware would like to thank the Fluoroacetate team of Amat Cama and
Richard Zhu, working with the Pwn2Own 2019 Security Contest, for
reporting these issues to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifiers CVE-2019-5518 (out-of-bounds read/write) and
CVE-2019-5519 (TOCTOU) to these issues.

b. VMware Workstation and Fusion out-of-bounds write vulnerability in
e1000 virtual network adapter

VMware Workstation and Fusion contain an out-of-bounds write
vulnerability in the e1000 virtual network adapter. This issue may
allow a guest to execute code on the host.

VMware would like to thank security researcher Zhangyanyu of Chaitin
Tech for reporting this issue to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2019-5524 to this issue.

c. VMware Workstation and Fusion out-of-bounds write vulnerability in
e1000 and e1000e virtual network adapters

VMware Workstation and Fusion updates address an out-of-bounds write
vulnerability in the e1000 and e1000e virtual network adapters.
Exploitation of this issue may lead to code execution on the host from
the guest but it is more likely to result in a denial of service of the
guest.

VMware would like to thank ZhanluLab working with Trend Micro's Zero
Day Initiative for reporting this issue to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2019-5515 to this issue.

d. VMware Fusion unauthenticated APIs Security vulnerability

VMware Fusion contains a security vulnerability due to certain
unauthenticated APIs accessible through a web socket. An attacker may
exploit this issue by tricking the host user to execute a JavaScript to
perform unauthorized functions on the guest machine where VMware Tools
is installed. This may further be exploited to execute commands on the
guest machines.

VMware would like to thank CodeColorist (@CodeColorist) and Csaba Fitzl
(@theevilbit) for independently reporting this issue to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2019-5514 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2019/000454.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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


init_esx_check(date:"2019-03-28");
flag = 0;


if (esx_check(ver:"ESXi 6.0", vib:"VMware:esx-base:6.0.0-3.113.13003896")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsan:6.0.0-3.113.12980971")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsanhealth:6.0.0-3000000.3.0.3.113.12980972")) flag++;

if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-base:6.5.0-2.83.13004031")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-tboot:6.5.0-2.83.13004031")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsan:6.5.0-2.83.12559347")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsanhealth:6.5.0-2.83.12559353")) flag++;

if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-base:6.7.0-1.41.13004448")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-update:6.7.0-1.41.13004448")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsan:6.7.0-1.41.12909115")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsanhealth:6.7.0-1.41.12909116")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
