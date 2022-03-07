#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124333);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/26 13:52:30");

  script_cve_id("CVE-2019-1805");
  script_bugtraq_id(108003);
  script_xref(name: "CWE", value: "CWE-284");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvk79421");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190417-wlc-ssh");
  script_xref(name: "IAVA", value: "2019-A-0132");

  script_name(english:"Cisco Wireless LAN Controller Secure Shell Unauthorized Access Vulnerability");
  script_summary(english:"Checks the version of Cisco Wireless LAN Controller (WLC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Wireless LAN Controller
(WLC) is affected by following vulnerability

  - A vulnerability in certain access control mechanisms for
    the Secure Shell (SSH) server implementation for Cisco
    Wireless LAN Controller (WLC) Software could allow an
    unauthenticated, adjacent attacker to access a CLI
    instance on an affected device.The vulnerability is due
    to a lack of proper input- and validation-checking
    mechanisms for inbound SSH connections on an affected
    device. An attacker could exploit this vulnerability by
    attempting to establish an SSH connection to an affected
    controller. An exploit could allow the attacker to
    access an affected device's CLI to potentially cause
    further attacks. (CVE-2019-1805)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-wlc-ssh
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk79421");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk79421");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1805");

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
  { 'min_ver' : '0.0', 'fix_ver' : '8.3.150.0' },
  { 'min_ver' : '8.4', 'fix_ver' : '8.5.140.0' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no workarounds']);
workaround_params = make_list();

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_NOTE,
'version'  , product_info['version'],
'bug_id'   , make_list("CSCvk79421")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
