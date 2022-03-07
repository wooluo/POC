#
# (C) WebRAY Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(123416);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/13  8:25:28");

  script_cve_id("CVE-2019-6798", "CVE-2019-6799");
  script_bugtraq_id(106727, 106736);

  script_name(english:"phpMyAdmin 4.x < 4.8.5 Multiple Vulnerabilities (PMASA-2019-1) (PMASA-2019-2)");
  script_summary(english:"Checks the version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin
application hosted on the remote web server is 4.x prior to
4.8.5. It is, therefore, affected by at least one of the following vulnerabilities:

  - A SQL injection (SQLi) vulnerability exists in phpMyAdmin due to improper validation of user-supplied input.
  An unauthenticated, remote attacker can exploit this to inject or manipulate SQL queries in the back-end database,
  resulting in the disclosure or manipulation of arbitrary data (CVE-2019-6798).

  - An arbitrary file read vulnerability exists in phpMyAdmin when the AllowArbitraryServer configuration setting is 
  set to true. An unauthenticated, remote attacker can exploit this, via a rogue MySQL server, to read arbitrary files
  and disclose sensitive information (CVE-2019-6799).

Note that GizaNE has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2019-1/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2019-2/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 4.8.5 or later.
Alternatively, apply the patches referenced in the vendor advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6798");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/phpMyAdmin");

  exit(0);
}
include("http.inc");
include("vcf.inc");

port = get_http_port(default:80, php:TRUE);
appname = "phpMyAdmin";
app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);

constraints = [{"min_version":"4.0", "fixed_version":"4.8.5"}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
