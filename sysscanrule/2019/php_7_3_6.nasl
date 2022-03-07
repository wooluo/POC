#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125681);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/03 13:37:30");

  script_cve_id("CVE-2019-11038", "CVE-2019-11039", "CVE-2019-11040");
  script_bugtraq_id(108514, 108520, 108525);
  script_xref(name:"IAVB", value:"2019-B-0045");

  script_name(english:"PHP 7.3.x < 7.3.6 Multiple Vulnerabilities.");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web server is 7.3.x prior to 7.3.6.
It is, therefore, affected by the following vulnerabilities:

  - An uninitialized vulnerability exists in gdImageCreateFromXbm due to sscanf method not being
  able to read a hex value. An attacker may be able exploit this issue,
  to cause the disclose of sensitive information. (CVE-2019-11038)

  - An out of bounds read vulnerability exists in iconv.c:_php_iconv_mime_decode() due to integer overflow.
  An attacker may be able exploit this issue, to cause the disclose of sensitive information. (CVE-2019-11039)

  - A heap-based buffer overflow condition exists on php_jpg_get16. An attacker can exploit this,
  to cause a denial of service condition or the execution of arbitrary code. (CVE-2019-11040)");

  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.3.6");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 7.3.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11040");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP", "installed_sw/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('audit.inc');

port = get_http_port(default:80, php:TRUE);
app = 'PHP';

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');
if ((report_paranoia < 2) && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

constraints = [{'min_version':'7.3.0alpha1', 'fixed_version':'7.3.6'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
