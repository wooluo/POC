##
# 
##

include('compat.inc');

if (description)
{
  script_id(145533);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2021-21615");

  script_name(english:"Jenkins < 2.263.3 LTS / 2.276 TOCTOU");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by a time-of-check to time-of-use race condition.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins running on the remote web server is prior to 2.276 weekly or 2.263.3 LTS. It is, therefore,
affected by a time-of-check to time-of-use (TOCTOU) race condition that allows reading arbitrary files using the file
browser for workspaces and archived artifacts.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.jenkins.io/security/advisory/2021-01-26/");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 2.276 or later, Jenkins LTS to version 2.263.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21615");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl");
  script_require_keys("www/Jenkins");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include('http.inc');
include('vcf.inc');

port = get_http_port(default:8080);
app = vcf::get_app_info(app:'Jenkins', webapp:TRUE, port:port);

if(app['LTS'])
  fixed_version = '2.263.3';
else
  fixed_version = '2.276';

constraints = [{'fixed_version' : fixed_version, 'fixed_display' : '2.263.3 LTS / 2.276'}];

vcf::check_version_and_report(
  app_info:app,
  constraints:constraints,
  severity:SECURITY_WARNING
);

