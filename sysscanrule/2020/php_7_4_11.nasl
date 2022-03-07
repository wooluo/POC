##
# 
##
include('compat.inc');

if (description)
{
  script_id(141355);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id("CVE-2020-7069", "CVE-2020-7070");
  script_xref(name:"IAVA", value:"2020-A-0445");

  script_name(english:"PHP 7.2 < 7.2.34 / 7.3.x < 7.3.23 / 7.4.x < 7.4.11 Mulitiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of PHP running on the remote web server is 7.2.x prior to 
7.2.34, 7.3.x prior to 7.3.23 or 7.4.x prior to 7.4.11. It is, therefore, affected by multiple vulnerabilties: 

  - A weak cryptography vulnerability exists in PHP's openssl_encrypt function due to a failure to utilize 
  all provided IV bytes. An unauthenticated, remote attacker could exploit this to reduce the level of 
  security provided by the encryption scheme or affect the integrity of the encrypted data (CVE-2020-7069).

  - A cookie forgery vulnerability exists in PHP's HTTP processing functionality. An unauthenticated, 
  remote could expoit this to forge HTTP cookies which were supposed to be secure. (CVE-2020-7070)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/79601");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/79699");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#7.2.34");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#7.3.23");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#7.4.11");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 7.2.34, 7.3.23, 7.4.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7069");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/09");

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

constraints = [
  {'min_version':'7.2.0alpha1', 'fixed_version':'7.2.34'},
  {'min_version':'7.3.0alpha1', 'fixed_version':'7.3.23'},
  {'min_version':'7.4.0alpha1', 'fixed_version':'7.4.11'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
