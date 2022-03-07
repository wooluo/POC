#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124168);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/25 16:22:16");

  script_cve_id(
    "CVE-2019-1003049",
    "CVE-2019-1003050"
  );
  script_bugtraq_id(
    107889,
    107901
  );

  script_name(english:"Jenkins < 2.164.2 LTS / 2.172 Multiple Vulnerabilities");
  script_summary(english:"Checks the Jenkins version.");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins running on the remote web server is prior to 2.172 or is a version of Jenkins LTS prior to
2.164.2. It is, therefore, affected by multiple vulnerabilities:

  - An authentication bypass condition exists due to an incomplete fix for SECURITY-901, in which existing
    remote-based CLI authentication caches. An unauthenticated, remote attacker can exploit this to bypass
    existing Access Control Limitations and appear as an authenticated user. (CVE-2019-1003049)

  - A cross-site scripting (XSS) vulnerability exists due to improper validation of user-supplied input before
    returning it to users. An unauthenticated, remote attacker can exploit this, by convincing a user to click
    a specially crafted URL, to execute arbitrary script code in a user's browser session. (CVE-2019-1003050)
    
Note that GizaNE has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2019-04-10/");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 2.172 or later, Jenkins LTS to version 2.164.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1003050");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/Jenkins");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('vcf.inc');

port = get_http_port(default:8080);
app = vcf::get_app_info(app:'Jenkins', webapp:TRUE, port:port);

if(app['LTS'])
  constraints = [{'fixed_version' : '2.164.2', 'fixed_display' : '2.164.2 LTS / 2.172'}];
else
  constraints = [{'fixed_version' : '2.172', 'fixed_display' : '2.164.2 LTS / 2.172'}];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
