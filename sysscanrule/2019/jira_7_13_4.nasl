#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125629);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/18 15:47:53");

  script_cve_id(
      "CVE-2019-3401",
      "CVE-2019-3402",
      "CVE-2019-3403",
      "CVE-2019-8442",
      "CVE-2019-8443"
      );
  script_bugtraq_id(
    108458,
    108460
  );

  script_name(english:"Atlassian JIRA < 7.13.4 / 8.0.x < 8.1.1 Multiple Vulnerabilities (SB19-147)");
  script_summary(english:"Checks the version of Atlassian JIRA.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially 
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of
Atlassian JIRA hosted on the remote web server is potentially
affected by multiple vulnerabilities:

  - A directory traversal vulnerability exists in the
    CachingResourceDownloadRewriteRule due to an ineffective path 
    access check. An unauthenticated, remote attacker can exploit 
    this by accessing files in the Jira webroot under the META-INF.
    (CVE-2019-8442)
  
  - A session management vulnerability exists in the administrators
    session due to improper access control. An unauthenticated, 
    remote attacker can exploit this to bypass WebSudo authentication
    and access the ViewUpgrades administrative resource. 
    (CVE-2019-8443)

  - An information disclosure vulnerability exists in the 
    ManageFilters.jspa and the /rest/api/2/user/picker rest resources 
    due to incorrect authorization checks. An unauthenticated, remote 
    attacker can exploit this to enumerate usernames. 
    (CVE-2019-3401, CVE-2019-3403)

  - A cross-site scripting (XSS) vulnerability exists due to improper
    validation of user-supplied input before returning it to users. 
    An unauthenticated, remote attacker can exploit this, by 
    convincing a user to click a specially crafted URL, to execute 
    arbitrary script code in a user's browser session.
   (CVE-2019-3402)
");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-69240");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-69241");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-69242");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-69244");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-69245");
  script_set_attribute(attribute:"see_also", value:"https://www.us-cert.gov/ncas/bulletins/SB19-147");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 7.13.4 / 8.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8442");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl");
  script_require_keys("installed_sw/Atlassian JIRA", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "Atlassian JIRA";

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:8080);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
constraints = [
  { "fixed_version" : "7.13.4" },
  { "min_version" : "8.0.0", "fixed_version" : "8.1.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
