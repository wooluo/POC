#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124060);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/30 14:30:16");

  script_cve_id("CVE-2019-1652", "CVE-2019-1653");
  script_xref(name:"CWE", value:"CWE-20");
  script_xref(name:"CWE", value:"CWE-284");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm78058");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg85922");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190123-rv-inject");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190123-rv-info");

  script_name(english:"Cisco Small Business RV320 and RV325 Routers Multiple Vulnerabilities (cisco-sa-20190123-rv-inject, cisco-sa-20190123-rv-info)");
  script_summary(english:"Checks the version of Cisco Small Business RV Series Router Firmware");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, this Cisco Small Business RV
Series router is affected by multiple vulnerabilities:

  - A vulnerability in the web-based management interface of
    Cisco Small Business RV320 and RV325 Dual Gigabit WAN
    VPN Routers could allow an authenticated, remote
    attacker with administrative privileges on an affected
    device to execute arbitrary commands.The vulnerability
    is due to improper validation of user-supplied input. An
    attacker could exploit this vulnerability by sending
    malicious HTTP POST requests to the web-based management
    interface of an affected device. A successful exploit
    could allow the attacker to execute arbitrary commands
    on the underlying Linux shell as root. (CVE-2019-1652)

  - A vulnerability in the web-based management interface of
    Cisco Small Business RV320 and RV325 Dual Gigabit WAN
    VPN Routers could allow an unauthenticated, remote
    attacker to retrieve sensitive information.The
    vulnerability is due to improper access controls for
    URLs. An attacker could exploit this vulnerability by
    connecting to an affected device via HTTP or HTTPS and
    requesting specific URLs. A successful exploit could
    allow the attacker to download the router configuration
    or detailed diagnostic information. (CVE-2019-1653)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190123-rv-inject
  script_set_attribute(attribute:"see_also", value:"");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190123-rv-info
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm78058");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg85922");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvm78058 & CSCvg85922");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1652");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco RV320 and RV325 Unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");


  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Device");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:'Cisco Small Business RV Series Router Firmware');

vuln_list = [
  {'min_ver' : '1.4.2.15', 'fix_ver' : '1.4.2.22'}
];

reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'fix'           , '1.4.2.22',
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvm78058 & CSCvg85922',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_list,
  models:make_list('RV320', 'RV325')
);
