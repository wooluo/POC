#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126446);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/19  7:51:59");

  script_cve_id("CVE-2019-1727");
  script_bugtraq_id(108341);
  script_xref(name:"IAVA", value:"2019-A-0173");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvi99284");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvh24788");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvi99282");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvi99288");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190515-nxos-pyth-escal");

  script_name(english:"Cisco NX-OS Software Python Parser Privilege Escalation Vulnerability");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Python scripting subsystem of Cisco NX-OS
Software could allow an authenticated, local attacker to escape the
Python parser and issue arbitrary commands to elevate the attacker's
privilege level. The vulnerability is due to insufficient
sanitization of user-supplied parameters that are passed to certain
Python functions in the scripting sandbox of the affected device.
An attacker could exploit this vulnerability to escape the scripting
sandbox and execute arbitrary commands to elevate the attacker's
privilege level. 

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-pyth-escal
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99284");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh24788");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99282");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99288");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bugs ID
CSCvi99284, CSCvh24788, CSCvi99282, CSCvi99288");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1727");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");
  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');


if (('MDS' >< product_info['device']) && (product_info['model'] =~ '^90[0-9][0-9]')) bugIDs = 'CSCvi99284';
else if ('Nexus' >< product_info['device'])
{
  if (product_info['model'] =~ '^3[05][0-9][0-9]' || product_info['model'] =~ '^90[0-9][0-9]') bugIDs = 'CSCvh24788';
  else if (product_info['model'] =~ '^36[0-9][0-9]' || product_info['model'] =~ '^95[0-9][0-9]') bugIDs = 'CSCvi99282';
  else if (product_info['model'] =~ '^7[07][0-9][0-9]') bugIDs = 'CSCvi99284';
}

if (isnull(bugIDs)) audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '8.2(2)',
  '8.2(1)',
  '8.1(1a)',
  '8.1(1)',
  '8.0(1)S2',
  '8.0(1)',
  '7.3(3)N1(1)',
  '7.3(2)N1(1)',
  '7.3(2)N1(0.296)',
  '7.3(2)D1(3a)',
  '7.3(2)D1(3)',
  '7.3(2)D1(2)',
  '7.3(2)D1(1A)',
  '7.3(2)D1(1)',
  '7.3(1)N1(1)',
  '7.3(1)N1(0.1)',
  '7.3(1)DY(1)',
  '7.3(1)D1(1B)',
  '7.3(1)D1(1)',
  '7.3(0.2)',
  '7.3(0)N1(1b)',
  '7.3(0)N1(1a)',
  '7.3(0)N1(1)',
  '7.3(0)DY(1)',
  '7.3(0)DX(1)',
  '7.3(0)D1(1)',
  '7.0(3)I7(2)',
  '7.0(3)I4(3)',
  '7.0(3)I4(2)',
  '7.0(3)I4(1)',
  '7.0(3)I3(1)',
  '7.0(3)I2(5)',
  '7.0(3)I2(4)',
  '7.0(3)I2(3)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2)',
  '7.0(3)I2(1a)',
  '7.0(3)I2(1)',
  '7.0(3)I1(3b)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3)',
  '7.0(3)I1(2)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(3b)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3)',
  '7.0(3)F3(2)',
  '7.0(3)F3(1)',
  '7.0(3)F2(2)',
  '7.0(3)F2(1)',
  '7.0(3)F1(1)',
  '7.0(3)',
  '7.0(2)N1(1a)',
  '7.0(2)N1(1)',
  '7.0(2)I2(2c)',
  '7.0(1)N1(3)',
  '7.0(1)N1(1)',
  '7.0(0)N1(1)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , bugIDs
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);