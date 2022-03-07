 #
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126916);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/22 15:30:52");

  script_cve_id("CVE-2019-1816");
  script_bugtraq_id(108131);
  script_xref(name: "CWE", value: "CWE-20");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvk68106");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190501-wsa-privesc");
  script_xref(name:"IAVA", value:"2019-A-0219");

  script_name(english:"Cisco Web Security Appliance Privilege Escalation Vulnerability");
  script_summary(english:"Checks the version of Cisco Web Security Appliance (WSA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Web Security Appliance
(WSA) is affected by following vulnerability

  - A vulnerability in the log subscription subsystem of the
    Cisco Web Security Appliance (WSA) could allow an
    authenticated, local attacker to perform command
    injection and elevate privileges to root.The
    vulnerability is due to insufficient validation of user-
    supplied input on the web and command-line interface. An
    attacker could exploit this vulnerability by
    authenticating to the affected device and injecting
    scripting commands in the scope of the log subscription
    subsystem. A successful exploit could allow the attacker
    to execute arbitrary commands on the underlying
    operating system and elevate privileges to root.
    (CVE-2019-1816)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-wsa-privesc
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk68106");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk68106");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:N/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1816");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance_(wsa)");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Web Security Appliance (WSA)");

vuln_ranges = [
  { 'min_ver' : '10.1', 'fix_ver' : '10.1.4-017' },
  { 'min_ver' : '10.5', 'fix_ver' : '10.5.4-018' },
  { 'min_ver' : '11.5', 'fix_ver' : '11.5.2-020' },
  { 'min_ver' : '11.7', 'fix_ver' : '11.7.0-406' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no workarounds']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , make_list("CSCvk68106")
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_ranges:vuln_ranges
);
