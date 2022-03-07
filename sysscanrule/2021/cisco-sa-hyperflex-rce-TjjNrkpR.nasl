##
# 
##

include('compat.inc');

if (description)
{
  script_id(149454);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/17");

  script_cve_id("CVE-2021-1497", "CVE-2021-1498");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx36014");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx36019");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx37435");
  script_xref(name:"CISCO-SA", value:"cisco-sa-hyperflex-rce-TjjNrkpR");
  script_xref(name:"IAVA", value:"2021-A-0237");

  script_name(english:"Cisco HyperFlex HX Command Injection Vulnerabilities (cisco-sa-hyperflex-rce-TjjNrkpR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco HyperFlex HX installed on the remote host is affected by multiple command injection 
vulnerabilities. An unauthenticated, remote attacker can exploit these to execute arbitrary commands on an affected 
system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-hyperflex-rce-TjjNrkpR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9228075");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx36014");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx36019");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx37435");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvx36014, CSCvx36019, CSCvx37435");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1497");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:hyperflex_hx-series_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_hyperflex_web_api_detect.nbin");
  script_require_keys("Host/OS/Cisco_HyperFlex_web_API");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var port = get_http_port(default:80);
var app_info = vcf::get_app_info(app:'Cisco HyperFlex', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  {'fixed_version':'4.0.2e'}, 
  {'min_version':'4.5.0', 'fixed_version':'4.5.2a'}
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);
