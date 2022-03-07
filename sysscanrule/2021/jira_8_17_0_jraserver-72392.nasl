
##
# 
##


include('compat.inc');

if (description)
{
  script_id(152865);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/30");

  script_cve_id("CVE-2021-26078");
  script_xref(name:"IAVA", value:"2021-A-0396");

  script_name(english:"Atlassian JIRA < 8.5.14 / 8.6.x < 8.13.6 / 8.14.x < 8.16.1 XSS (JRASERVER-72392)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian JIRA hosted on the remote web server is
affected by a cross-site scripting vulnerability in the number range searcher component due to improper validation of
user-supplied input before returning it to users. An unauthenticated, remote attacker can exploit this, by convincing a
user to click a specially crafted URL, to execute arbitrary script code in a user's browser session. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-72392");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 8.5.14 / 8.13.6 / 8.16.1 / 8.17.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26078");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

var constraints = [
  { 'fixed_version':'8.5.14' },
  { 'min_version':'8.6.0', 'fixed_version':'8.13.6' },
  { 'min_version':'8.14.0', 'fixed_version':'8.16.1', 'fixed_display':'8.16.1 / 8.17.0' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
