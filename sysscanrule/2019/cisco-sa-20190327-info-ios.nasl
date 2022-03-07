#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127098);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/29  4:58:54");

  script_cve_id("CVE-2019-1762");
  script_bugtraq_id(107594);

  script_xref(name:"IAVA", value:"2019-A-0264");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvg97571");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190327-info");

  script_name(english:"Cisco IOS Software Information Disclosure Vulnerability (cisco-sa-20190327-info)");
  script_summary(english:"Checks the version of Cisco IOS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS Software is
affected by an unspecified vulnerability in the Secure Storage
feature of Cisco IOS that allows an authenticated, local attacker
to access sensitive system information on an affected device. The
vulnerability is due to improper memory operations performed at
encryption time, when affected software handles configuration
updates. An attacker can exploit this vulnerability by retrieving
the contents of specific memory locations of an affected device.
A successful exploit could result in the disclosure of keying
materials that are part of the device configuration, which can be
used to recover critical system information. (CVE-2019-1762)

Please see the included Cisco BID and Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-info
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg97571");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvg97571.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1762");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list = make_list(
  '12.2(6)I1',
  '15.1(2)SG8a',
  '15.1(3)SVG3d',
  '15.1(3)SVI1b',
  '15.1(3)SVM3',
  '15.1(3)SVN2',
  '15.1(3)SVO1',
  '15.1(3)SVO2',
  '15.1(3)SVP1',
  '15.2(3)EA1',
  '15.2(4)JN1',
  '15.2(4a)EA5',
  '15.3(3)JA1n',
  '15.3(3)JF35',
  '15.6(2)SP3b',
  '15.6(3)M1',
  '15.6(3)M1a',
  '15.6(3)M1b',
  '15.6(3)M2',
  '15.6(3)M2a',
  '15.6(3)M3',
  '15.6(3)M3a',
  '15.6(3)M4',
  '15.7(3)M',
  '15.7(3)M0a',
  '15.7(3)M1'
);

workarounds = make_list(CISCO_WORKAROUNDS['service_private_config_encryption']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvg97571',
  'cmds'     , make_list('show running-config all | include service private-config-encryption')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
