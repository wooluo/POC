##
# 
##
include('compat.inc');

if (description)
{
  script_id(144947);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2020-7071");
  script_name(english:"PHP 7.3.x < 7.3.26 / 7.4.x < 7.4.14 / 8.x < 8.0.1 Input Validation Error");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by an input validation error");
  script_set_attribute(attribute:"description", value:
"The version of PHP installed on the remote host is 7.3.x prior to 7.3.26, 7.4.x prior to 7.4.14, or 8.x prior to 8.0.1.
It is, therefore, affected by an input validation error due to insufficient validation of a URL, as specified by the
changelogs of the respective fixed releases. An unauthenticated, remote attacker can exploit this, by including an '@'
character, in order to bypass the URL filter.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#7.3.26");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#7.4.14");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-8.php#8.0.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.3.26, 7.4.14, 8.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7071");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP", "installed_sw/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'PHP', port:port, webapp:TRUE);

backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');
if ((report_paranoia < 2) && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

constraints = [
  {'min_version':'7.3.0alpha1', 'fixed_version':'7.3.26'},
  {'min_version':'7.4.0alpha1', 'fixed_version':'7.4.14'},
  {'min_version':'8.0.0alpha1', 'fixed_version':'8.0.1'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
