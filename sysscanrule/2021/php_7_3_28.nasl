
##
# 
##


include('compat.inc');

if (description)
{
  script_id(152853);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/26");

  script_name(english:"PHP < 7.3.28 Email Header Injection");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by an email header injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of PHP running on the remote web server is prior to 7.3.28.
It is, therefore affected by an email header injection vulnerability, due to a failure to properly handle CR-LF
sequences in header fields. An unauthenticated, remote attacker can exploit this, by inserting line feed characters
into email headers, to gain full control of email header content.");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#7.3.28");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.3.28 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/26");

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

var port = get_http_port(default:80, php:TRUE);
var app_info = vcf::get_app_info(app:'PHP', port:port, webapp:TRUE);

var backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');
if ((report_paranoia < 2) && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

var constraints = [{'min_version':'1.0.0', 'fixed_version':'7.3.28'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
