#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124774);
  script_version("1.5");
  script_cvs_date("Date: 2019/06/24  8:13:25");

  script_cve_id("CVE-2019-1642");
  script_bugtraq_id(106714);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190123-frpwr-mc-xss");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk30983");
  script_xref(name:"IAVA", value:"2019-A-0204");

  script_name(english:"Cisco Firepower Management Center XSS Vulnerability");
  script_summary(english:"Checks the version of Cisco Firepower Management Center.");

  script_set_attribute(attribute:"synopsis", value:
"A network management application installed on the remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Firepower Management Center is by a cross-site scripting (XSS)
vulnerability due to improper validation of user-supplied input before returning it to users. An unauthenticated,
remote attacker can exploit this, by convincing a user to click a specially crafted URL, to execute arbitrary script
code in a user's browser session.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190123-frpwr-mc-xss
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvk30983.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1642");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2019/01/23");
  script_set_attribute(attribute:"patch_publication_date",value:"2019/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/10");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower_management_center");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');
include('lists.inc');

app = 'Cisco Firepower Management Center';
app_info = vcf::get_app_info(app:app, kb_ver:'Host/Cisco/firepower_mc/version');

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {'min_version': '6.2.3', 'fixed_version': '6.2.3.7'}
];

if (report_paranoia == 2)
  collib::push({'equal': '6.3.0', 'fixed_display': 'See vendor advisory'}, constraints);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss': TRUE});
