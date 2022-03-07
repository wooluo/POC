##
# 
##

include('compat.inc');

if (description)
{
  script_id(149348);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/07");

  script_xref(name:"IAVA", value:"2021-A-0210");

  script_name(english:"PHP 7.4.x < 7.4.18 / 8.x < 8.0.5 Integer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by an integer overflow condition.");
  script_set_attribute(attribute:"description", value:
"The version of PHP installed on the remote host is 7.4.x prior to 7.4.18, or 8.x prior to 8.0.5. It is, therefore,
affected by an integer overflow condition in pnctl_exec(). An attacker can exploit this to cause a denial of service
(DoS) condition or the execution of arbitrary code.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#7.4.18");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-8.php#8.0.5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.4.18, 8.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

var port = get_http_port(default:80, php:TRUE);
var app_info = vcf::get_app_info(app:'PHP', port:port, webapp:TRUE);

var backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');
if ((report_paranoia < 2) && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

var constraints = [
  {'min_version':'7.4.0alpha1', 'fixed_version':'7.4.18'},
  {'min_version':'8.0.0alpha1', 'fixed_version':'8.0.5'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
