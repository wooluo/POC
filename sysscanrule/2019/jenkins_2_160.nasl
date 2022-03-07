#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121330);
  script_version("1.4");
  script_cvs_date("Date: 2019/04/18 12:05:36");

  script_cve_id(
    "CVE-2019-1003003",
    "CVE-2019-1003004"
  );

  script_name(english:"Jenkins < 2.150.2 LTS / 2.160 Multiple Vulnerabilities");
  script_summary(english:"Checks the Jenkins version.");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web
server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins running on the remote web server is prior to
2.160 or is a version of Jenkins LTS prior to 2.150.2. It is,
therefore, affected by multiple vulnerabilities:

An improper authorization vulnerability exists in the Hudson CI tool
as part of Jenkins Core due to inadequate validation. An
authenticated, remote attacker can exploit this, by crafting Remember 
Me cookies that would never expire, allowing e.g. to persist access
to temporarily compromised user accounts, or by extending the duration
of active HTTP sessions indefinitely even though the user account may
have been deleted in the mean time.

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2019-01-16/");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 2.160 or later, Jenkins LTS to version
2.150.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1003003");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/23");

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
  constraints = [{'fixed_version' : '2.150.2', 'fixed_display' : '2.150.2 LTS / 2.160'}];
else
  constraints = [{'fixed_version' : '2.160', 'fixed_display' : '2.150.2 LTS / 2.160'}];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
