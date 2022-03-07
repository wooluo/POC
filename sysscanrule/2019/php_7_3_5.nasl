#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124764);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/07 10:32:27");

  script_cve_id("CVE-2019-11036");

  script_name(english:"PHP 7.3.x < 7.3.5 Heap-based Buffer Overflow Vulnerability.");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a heap-based buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web server is 7.3.x prior to 7.3.5. It is, therefore,
affected by a heap-based buffer over-read condition within _estrndup of the exif_process_IFD_TAG in the exif.c script.
An unauthenticated, remote attacker can exploit this, to cause a denial of service condition or the execution of
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.3.5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.3.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11036");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('webapp_func.inc');

fix = '7.3.5';
minver = '7.3.0alpha1';

regexes = make_array(
  -3, 'alpha(\\d+)',
  -2, 'beta(\\d+)',
  -1, 'RC(\\d+)'
);

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

ver = php["ver"];
source = php["src"];
backported = get_kb_item('www/php/' + port + '/' + ver + '/backported');

if ((report_paranoia < 2) && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + ver + ' install');

vulnerable = ver_compare(minver:minver, ver:ver, fix:fix, regexes:regexes);
if (isnull(vulnerable)) exit(1, 'The version of PHP ' + ver + ' is not within the checked ranges.');
if (vulnerable > -1) audit(AUDIT_LISTEN_NOT_VULN, 'PHP', port, ver);

report =
'\n  Version source    : ' + source +
'\n  Installed version : ' + ver +
'\n  Fixed version     : ' + fix +
'\n';
security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);