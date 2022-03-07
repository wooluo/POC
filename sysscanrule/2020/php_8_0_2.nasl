##
# 
##

include('compat.inc');

if (description)
{
  script_id(146311);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2021-21702");
  script_xref(name:"IAVA", value:"2021-A-0082");

  script_name(english:"PHP 7.3.x < 7.3.27 / 7.4.x < 7.4.15 / 8.x < 8.0.2 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of PHP installed on the remote host is 7.3.x prior to 7.3.27, 7.4.x prior to 7.4.15, or 8.x prior to 8.0.2.
It is, therefore, affected by a denial of service (DoS) vulnerability due to a null dereference in SoapClient. An
unauthenticated, remote attacker can exploit this,  by providing an XML to the SoapCLient query() function without an
existing field, in order to cause PHP to crash.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#7.3.27");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#7.4.15");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-8.php#8.0.2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.3.27, 7.4.15, 8.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21702");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/09");

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

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'PHP', port:port, webapp:TRUE);

backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');
if ((report_paranoia < 2) && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

constraints = [
  {'min_version':'7.3.0alpha1', 'fixed_version':'7.3.27'},
  {'min_version':'7.4.0alpha1', 'fixed_version':'7.4.15'},
  {'min_version':'8.0.0alpha1', 'fixed_version':'8.0.2'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
