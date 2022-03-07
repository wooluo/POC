##
# 
##

include('compat.inc');

if (description)
{
  script_id(145248);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/22");

  script_cve_id(
    "CVE-2021-21602",
    "CVE-2021-21603",
    "CVE-2021-21604",
    "CVE-2021-21605",
    "CVE-2021-21606",
    "CVE-2021-21607",
    "CVE-2021-21608",
    "CVE-2021-21609",
    "CVE-2021-21610",
    "CVE-2021-21611"
  );

  script_name(english:"Jenkins < 2.263.2 LTS / 2.275 Multiple Vulnerabilities");
  script_summary(english:"Checks the Jenkins version.");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins running on the remote web server is prior to 2.275 or is a version of Jenkins LTS prior to
2.263.2. It is, therefore, affected by multiple vulnerabilities, including the following:

  - Jenkins 2.274 and earlier, LTS 2.263.1 and earlier allows users with Agent/Configure permission to choose agent
    names that cause Jenkins to override the global `config.xml` file. (CVE-2021-21605)

  - Jenkins 2.274 and earlier, LTS 2.263.1 and earlier allows attackers with permission to create or configure various
    objects to inject crafted content into Old Data Monitor that results in the instantiation of potentially unsafe
    objects once discarded by an administrator. (CVE-2021-21604)

  - Jenkins 2.274 and earlier, LTS 2.263.1 and earlier does not correctly match requested URLs to the list of always
    accessible paths, allowing attackers without Overall/Read permission to access some URLs as if they did have
    Overall/Read permission. (CVE-2021-21609)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.jenkins.io/security/advisory/2021-01-13/");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 2.275 or later, Jenkins LTS to version 2.263.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21605");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/22");

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
  fixed_version = '2.263.2';
else
  fixed_version = '2.275';

constraints = [{'fixed_version' : fixed_version, 'fixed_display' : '2.263.2 LTS / 2.275'}];

vcf::check_version_and_report(
  app_info:app,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);

