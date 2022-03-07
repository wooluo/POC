##
# 
##
include('compat.inc');

if (description)
{
  script_id(146103);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2020-36231");
  script_xref(name:"IAVA", value:"2021-A-0060");

  script_name(english:"Atlassian JIRA < 8.5.10 / 8.6.x < 8.13.2 Information Disclosure (JRASERVER-72002)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian JIRA hosted on the remote web server is 
affected by an information disclosure vulnerability in its boards component due to missing permission checks. An 
authenticated, remote attacker can exploit this, to enumerate board metadata.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-72002");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 8.5.10 / 8.13.2 / 8.14.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36231");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"agent", value:"all");
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
  {'fixed_version':'8.5.10'},
  {'min_version':'8.6.0', 'fixed_version':'8.13.2', 'fixed_display':'8.13.2 / 8.14.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
