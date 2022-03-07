#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126823);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/22 10:22:12");

  script_cve_id("CVE-2019-1844");
  script_bugtraq_id(108149);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm36810");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-esa-bypass");
  script_xref(name:"IAVA", value:"2019-A-0243");

  script_name(english:"Cisco Email Security Appliance Filter Bypass Vulnerability (cisco-sa-20190501-esa-bypass)");
  script_summary(english:"Checks the version of Cisco Email Security Appliance (ESA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance
(ESA) is affected by following vulnerability

  - A vulnerability in certain attachment detection
    mechanisms of the Cisco Email Security Appliance (ESA)
    could allow an unauthenticated, remote attacker to
    bypass the filtering functionality of an affected
    device.The vulnerability is due to improper detection of
    certain content sent to an affected device. An attacker
    could exploit this vulnerability by sending certain file
    types without Content-Disposition information to an
    affected device. A successful exploit could allow an
    attacker to send messages that contain malicious content
    to users. (CVE-2019-1844)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-esa-bypass
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm36810");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvm36810");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1844");
  script_cwe_id(20);
  script_set_attribute(attribute:"potential_vulnerability", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

vuln_list = [
  {'min_ver' : '0', 'fix_ver' : '11.1.1.030'},
  {'min_ver' : '11.1.2.0', 'fix_ver' : '11.1.2.023'},
  {'min_ver' : '12.0.0.0', 'fix_ver' : '12.0.0.419'},
  {'min_ver' : '12.1.0.0', 'fix_ver' : '12.1.0.071'}
];

if(product_info['version'] =~ "^11\.1\.2\.") fixed='11.1.2-023';
else if(product_info['version'] =~ "^12\.0\.") fixed='12.0.0-419';
else if(product_info['version'] =~ "^12\.1\.") fixed='12.1.0-071';
else fixed='11.1.1-030';

workarounds = make_list(CISCO_WORKAROUNDS['no workarounds']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['display_version'],
'fix'      , fixed
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_list);
