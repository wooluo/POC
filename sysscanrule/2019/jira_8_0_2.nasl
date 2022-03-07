#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124772);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/10 15:10:59");

  script_cve_id("CVE-2019-3400");
  script_bugtraq_id(108168);
  script_xref(name:"IAVA", value:"2019-A-0141");

  script_name(english:"Atlassian JIRA Cross-Site Scripting (XSS) Vulnerability (JRASERVER-69245)");
  script_summary(english:"Checks the version of Atlassian JIRA.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian JIRA hosted on the remote web server is prior
to 7.13.2 or 8.0.x prior to 8.0.2. It is, therefore, affected by a cross-site scripting (XSS) vulnerability due to 
improper validation of user-supplied input before returning it to users. An unauthenticated, remote attacker can 
exploit this, by convincing a user to click a specially crafted URL, to execute arbitrary script code in a user's 
browser session.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-69245");
  script_set_attribute(attribute:"solution", value:"Upgrade to Atlassian JIRA version 7.13.2 / 8.0.2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3400");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"CGI abuses");

  script_dependencies("jira_detect.nasl");
  script_require_keys("installed_sw/Atlassian JIRA", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:8080);
app_info = vcf::get_app_info(app:"Atlassian JIRA", port:port, webapp:TRUE);

constraints = [
  { 'fixed_version' : '7.13.2' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.2' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
