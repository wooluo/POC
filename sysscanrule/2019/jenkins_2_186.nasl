#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127053);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/26 15:17:09");

  script_cve_id(
    "CVE-2019-10352",
    "CVE-2019-10353",
    "CVE-2019-10354"
  );
  script_bugtraq_id(
    109299,
    109373
  );
  script_xref(name:"TRA", value:"TRA-2019-35");
  script_xref(name:"IAVA", value:"2019-A-0262");

  script_name(english:"Jenkins < 2.176.2 LTS / 2.186 Multiple Vulnerabilities");
  script_summary(english:"Checks the Jenkins version.");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins running on the remote web server is prior to 2.186 or is a version of Jenkins LTS prior to
2.176.2. It is, therefore, affected by multiple vulnerabilities:

  - An arbitrary file write vulnerability exists due to an incomplete fix for SECURITY-1074, the improper
    validation of the file parameter definition. An authenticated, remote attacker can exploit this, via a
    file name with a relative path escaping the base directory, to write arbitrary files on the remote host.
    (CVE-2019-10352)

  - A security bypass vulnerability exists due to insufficent validaiton of CSRF tokens. An unauthenticated,
    remote attacker can exploit this, after obtaining the CSRF token of another user, to bypass CSRF
    protections and implement a CSRF attack. (CVE-2019-10353)

  - An information disclosure vulnerability exists in the Stapler web framework due to inadequit permission
    control of view fragments. An authenticated, remote attacker can exploit this, to disclose potentially
    sensitive information. (CVE-2019-10354)

Note that GizaNE has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2019-07-17/");
  script_set_attribute(attribute:"see_also", value:"https://www.WebRAY.com/security/research/tra-2019-35");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 2.186 or later, Jenkins LTS to version 2.176.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10353");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  constraints = [{'fixed_version' : '2.176.2', 'fixed_display' : '2.176.2 LTS / 2.186'}];
else
  constraints = [{'fixed_version' : '2.186', 'fixed_display' : '2.176.2 LTS / 2.186'}];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
