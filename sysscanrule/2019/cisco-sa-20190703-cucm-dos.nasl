#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126644);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/12 15:23:30");

  script_cve_id("CVE-2019-1887");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvo70834");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190703-cucm-dos");
  script_xref(name:"IAVA", value:"2019-A-0216");

  script_name(english:"Cisco Unified Communications Manager Session Initiation Protocol Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco Unified Communications Manager");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager is affected by a vulnerability in the
Session Initiation Protocol (SIP) protocol implementation could allow an unauthenticated, remote attacker to cause a
denial of service (DoS) condition. The vulnerability is due to insufficient validation of input SIP traffic. An attacker
could exploit this vulnerability by sending a malformed SIP packet to an affected Cisco Unified Communications Manager.
A successful exploit could allow the attacker to trigger a new registration process on all connected phones, temporarily
disrupting service. Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190703-cucm-dos
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo70834");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo70834");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1887");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");
  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Unified Communications Manager");

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '10.5.2.17900.13'},
  {'min_ver' : '11.5', 'fix_ver' : '11.5.1.15900.18'},
  {'min_ver' : '12.0', 'fix_ver' : '12.0.1.22900.11'},
  {'min_ver' : '12.5', 'fix_ver' : '12.5.1.10000.22'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['display_version'],
  'bug_id'   , 'CSCvo70834');

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
