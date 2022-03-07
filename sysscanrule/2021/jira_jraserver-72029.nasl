##
# 
##

include('compat.inc');

if (description)
{
  script_id(148265);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/02");

  script_cve_id("CVE-2021-26070");
  script_xref(name:"IAVA", value:"2021-A-0150");

  script_name(english:"Atlassian Jira < 8.13.3 / 8.14.x < 8.14.1 Broken Authentication (JRASERVER-72029)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a broken authentication vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian Jira hosted on the remote web server is
affected by a broken authentication vulnerability in the makeRequest gadget resource. An unauthenticated, remote 
attacker can exploit this issue to evade behind-the-firewall protection of app-linked resources.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-72029");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira version 8.13.3, 8.14.1, 8.15.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26070");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');

app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

constraints = [
  {'fixed_version':'8.13.3'},
  {'min_version':'8.14.0', 'fixed_version':'8.14.1', 'fixed_display':'8.14.1, 8.15.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
