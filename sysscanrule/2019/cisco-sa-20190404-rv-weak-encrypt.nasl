#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124061);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/15 13:55:15");

  script_cve_id("CVE-2019-1827", "CVE-2019-1828");
  script_xref(name: "CWE", value: "CWE-327");
  script_xref(name: "CWE", value: "CWE-79");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvp09589");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvp09573");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190404-rv-xss");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190404-rv-weak-encrypt");

  script_name(english:"Cisco Small Business RV320 and RV325 Routers Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Cisco Small Business RV Series Router Firmware");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, this Cisco Small Business RV
Series router is affected by multiple vulnerabilities:

  - A vulnerability in the Online Help web service of Cisco
    Small Business RV320 and RV325 Dual Gigabit WAN VPN
    Routers could allow an unauthenticated, remote attacker
    to conduct a reflected cross-site scripting (XSS) attack
    against a user of the service.The vulnerability exists
    because the Online Help web service of an affected
    device insufficiently validates user-supplied input. An
    attacker could exploit this vulnerability by persuading
    a user of the service to click a malicious link. A
    successful exploit could allow the attacker to execute
    arbitrary script code in the context of the affected
    service or access sensitive browser-based information.
    (CVE-2019-1827)

  - A vulnerability in the web-based management interface of
    Cisco Small Business RV320 and RV325 Dual Gigabit WAN
    VPN Routers could allow an unauthenticated, remote
    attacker to access administrative credentials.The
    vulnerability exists because affected devices use weak
    encryption algorithms for user credentials. An attacker
    could exploit this vulnerability by conducting a man-in-
    the-middle attack and decrypting intercepted
    credentials. A successful exploit could allow the
    attacker to gain access to an affected device with
    administrator privileges. (CVE-2019-1828)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190404-rv-xss
  script_set_attribute(attribute:"see_also", value:"");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190404-rv-weak-encrypt
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp09589");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp09573");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvp09589 & CSCvp09573");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1828");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/04");
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
  {'min_ver' : '0', 'fix_ver' : '1.4.2.22'}
];

reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'fix'           , '1.4.2.22',
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvp09589 & CSCvp09573',
  'disable_caveat', TRUE,
  'xss'           , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_list,
  models:make_list('RV320', 'RV325')
);
