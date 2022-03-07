#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126342);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/28 16:45:47");

  script_cve_id("CVE-2019-1767", "CVE-2019-1768");
  script_bugtraq_id(108386);
  script_xref(name: "CISCO-BUG-ID", value: "CSCvh76132");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvh76129");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvj00497");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvj10162");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190515-nxos-overflow-inj");
  script_xref(name: "IAVA", value:"2019-A-0173");

  script_name(english:"Cisco NX-OS Software Buffer Overflow and Command Injection Vulnerabilities");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is
affected by a vulnerability in the implementation of a specific CLI
command for Cisco NX-OS Software could allow an authenticated, local
attacker with administrator credentials to cause a buffer overflow
condition  or perform command injection. This could allow the
attacker to execute arbitrary commands with elevated privileges
on the underlying operating system of an affected device. The
vulnerability is due to insufficient validation of arguments
passed to a certain CLI command. An attacker could exploit this
vulnerability by including malicious input as the argument of
the affected CLI command. A successful exploit could allow
the attacker to execute arbitrary commands on the underlying
operating system with root privileges. An attacker would need
valid administrator credentials to exploit this vulnerability.
(CVE-2019-1767) (CVE-2019-1768)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-overflow-inj
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh76132");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh76129");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj00497");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj10162");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCvh76132, CSCvh76129, CSCvj00497, CSCvj10162");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1767");
  script_cwe_id(119, 119, 77, 77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/28");

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
bugIDs = NULL;

if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^3[05][0-9][0-9]' || product_info.model =~ '^90[0-9][0-9]') bugIDs = 'CSCvh76132, CSCvh76129';
  else if (product_info.model =~ '^36[0-9][0-9]' || product_info.model =~ '^95[0-9][0-9]') bugIDs = 'CSCvj00497, CSCvj10162';
}

if (isnull(bugIDs)) audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '7.0',
  '7.0(0)N1',
  '7.0(0)N1(1)',
  '7.0(1)N1',
  '7.0(1)N1(1)',
  '7.0(1)N1(3)',
  '7.0(2)I2',
  '7.0(2)I2(2c)',
  '7.0(2)N1',
  '7.0(2)N1(1)',
  '7.0(2)N1(1a)',
  '7.0(3)',
  '7.0(3)F1',
  '7.0(3)F1(1)',
  '7.0(3)F2',
  '7.0(3)F2(1)',
  '7.0(3)F2(2)',
  '7.0(3)F3',
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3b)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(4)',
  '7.0(3)I1',
  '7.0(3)I1(1)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(2)',
  '7.0(3)I1(3)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3b)',
  '7.0(3)I2',
  '7.0(3)I2(1)',
  '7.0(3)I2(1a)',
  '7.0(3)I2(2)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(3)',
  '7.0(3)I2(4)',
  '7.0(3)I2(5)',
  '7.0(3)I3',
  '7.0(3)I3(1)',
  '7.0(3)I4',
  '7.0(3)I4(1)',
  '7.0(3)I4(2)',
  '7.0(3)I4(3)',
  '7.0(3)I4(4)',
  '7.0(3)I4(5)',
  '7.0(3)I4(6)',
  '7.0(3)I4(7)',
  '7.0(3)I5',
  '7.0(3)I5(1)',
  '7.0(3)I5(2)',
  '7.0(3)I6',
  '7.0(3)I6(1)',
  '7.0(3)I6(2)',
  '7.0(3)I7',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(5a)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no workarounds']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , bugIDs
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
