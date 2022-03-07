#
# 
#

include('compat.inc');

if (description)
{
  script_id(140532);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/11");

  script_xref(name:"IAVA", value:"2020-A-0420");

  script_name(english:"PHP 7.2.x / 7.3.x < 7.3.22 Memory Leak Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by a memory
leak vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of PHP running on
the remote web server is 7.2.x or 7.3.x prior to 7.3.21. It is, therefore
affected by a memory leak vulnerability in the LDAP component. An
unauthenticated, remote attacker could exploit this issue to cause a
denial-of-service condition.");

  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#7.3.22");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.3.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"DoS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

constraints = [{'min_version':'7.2', 'fixed_version':'7.3.22'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

