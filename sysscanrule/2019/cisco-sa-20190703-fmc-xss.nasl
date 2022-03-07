#
# (C) WebRAY Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(127121);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:38");

  script_cve_id("CVE-2019-1930", "CVE-2019-1931");
  script_bugtraq_id(109047);

  
  script_xref(name:"IAVA", value:"2019-A-0269");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo90805");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo92913");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190703-fmc-xss");

  script_name(english:"Cisco Firepower Management Center 6.2.3.x < 6.2.3.14 / 6.3.0.x < 6.3.0.4 / 6.4.0.x < 6.4.0.2 XSS (cisco-sa-20190703-fmc-xss)");
  script_summary(english:"Checks the version of Cisco Firepower Management Center");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Management Center is affected by multiple vulnerabilities.
Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # http://tools.cisco.com/security/center/content/CiscoAppliedMitigationBulletin/cisco-amb-20060922-understanding-xss
  script_set_attribute(attribute:"see_also", value:"");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190703-fmc-xss
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo90805");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo92913");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvo90805, CSCvo92913");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1930");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_management_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {'min_version': '6.2.3', 'fixed_version': '6.2.3.14'},
  {'min_version': '6.3.0', 'fixed_version': '6.3.0.4'},
  {'min_version': '6.4.0', 'fixed_version': '6.4.0.2'}
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING, 
  flags:{'xss': TRUE}
);
