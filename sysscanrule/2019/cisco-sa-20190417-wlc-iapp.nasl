#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124332);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/06 16:43:34");

  script_cve_id("CVE-2019-1796", "CVE-2019-1799", "CVE-2019-1800");
  script_xref(name: "CWE", value: "CWE-399");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvh91032");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvh96364");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvi89027");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190417-wlc-iapp");
  script_xref(name: "IAVA", value: "2019-A-0132");

  script_name(english:"Cisco Wireless LAN Controller Software IAPP Message Handling Denial of Service Vulnerabilities");
  script_summary(english:"Checks the version of Cisco Wireless LAN Controller (WLC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Wireless LAN Controller
(WLC) is affected by following multiple vulnerabilities

  - Multiple vulnerabilities in the handling of Inter-Access
    Point Protocol (IAPP) messages by Cisco Wireless LAN
    Controller (WLC) Software could allow an
    unauthenticated, adjacent attacker to cause a denial of
    service (DoS) condition.The vulnerabilities exist
    because the software improperly validates input on
    fields within IAPP messages. An attacker could exploit
    the vulnerabilities by sending malicious IAPP messages
    to an affected device. A successful exploit could allow
    the attacker to cause the Cisco WLC Software to reload,
    resulting in a DoS condition. (CVE-2019-1799,
    CVE-2019-1796, CVE-2019-1800)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-wlc-iapp
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh91032");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh96364");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi89027");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCvh91032, CSCvh96364, CSCvi89027");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1799");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_(wlc)");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version");
  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Wireless LAN Controller (WLC)");

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '8.2.170.0' },
  { 'min_ver' : '8.3', 'fix_ver' : '8.3.150.0' },
  { 'min_ver' : '8.4', 'fix_ver' : '8.5.140.0' },
  { 'min_ver' : '8.6', 'fix_ver' : '8.8.100.0' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no workarounds']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , make_list("CSCvh96364", "CSCvh96364", "CSCvh96364")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
