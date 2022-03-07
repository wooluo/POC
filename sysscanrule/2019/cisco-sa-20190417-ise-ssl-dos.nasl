#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126101);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/21 16:44:58");

  script_cve_id("CVE-2019-1718");
  script_bugtraq_id(108030);
  script_xref(name: "CISCO-BUG-ID", value: "CSCvo10487");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190417-ise-ssl-dos");
  script_xref(name: "IAVA", value: "2019-A-0206");

  script_name(english:"Cisco Identity Services Engine SSL Renegotiation Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco Identity Services Engine Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Software is affected by a vulnerability in the
web interface of Cisco Identity Services Engine (ISE) could allow an unauthenticated, remote attacker to trigger high
CPU usage, resulting in a denial of service (DoS) condition. The vulnerability is due to improper handling of Secure
Sockets Layer (SSL) renegotiation requests. An attacker could exploit this vulnerability by sending renegotiation
requests at a high rate. An successful exploit could increase the resource usage on the system, eventually leading to a
DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-ise-ssl-dos
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo10487");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo10487");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1718");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:identity_services_engine");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");


  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version", "Settings/ParanoidReport");
  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
  { 'min_ver' : '2.1.0', fix_ver : '2.2.0.470' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no workarounds']);
workaround_params = make_list();

# ISE version doesn't change when patches are installed, so even if 
# they are on the proper version we have to double check patch level
required_patch = '';
if (product_info['version'] =~ "^2\.2\.0($|[^0-9])") required_patch = '14';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo10487',
  'fix'      , '2.2.0.470 Patch 14'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges, required_patch:required_patch);
