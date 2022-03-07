#
# 
#

include('compat.inc');

if (description)
{
  script_id(139066);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/30");

  script_cve_id("CVE-2019-20410");
  script_xref(name:"IAVA", value:"2020-A-0284");

  script_name(english:"Atlassian Jira < 7.6.17 / 7.7.x < 7.13.9 / 8.0.x < 8.4.2 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian Jira hosted on the remote web server is
prior to 7.6.17, or 7.7.x prior to 7.13.9, or version 8.0.x prior to 8.4.2. It is, therefore, affected by a Information
Disclosure vulnerability.

  - A remote attackers to view sensitive information via an Information Disclosure vulnerability in the comment
    restriction feature.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-70884");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira version 7.6.17, 7.13.9, 8.4.2, 8.5.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20410");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');

app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

constraints = [
  { 'fixed_version' : '7.6.17' },
  { 'min_version' : '7.7.0', 'fixed_version' : '7.13.9' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.4.2',   'fixed_display' : '8.4.2 / 8.5.0' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);