#
# (C) WebRAY Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(125856);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/18 10:31:32");

  script_cve_id("CVE-2019-12616");
  script_bugtraq_id(108619);

  script_name(english:"phpMyAdmin 4.x < 4.9.0 CSRF vulnerablity (PMASA-2019-4)");
  script_summary(english:"Checks the version of phpMyAdmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by a CSRF vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the phpMyAdmin application hosted on the remote
web server is 4.x prior to 4.9.0. It is, therefore, affected by a cross-site request forgery (XSRF)
vulnerability. A remote attacker can exploit this by tricking a user into visiting a specially
crafted web page, allowing the attacker to disclose sensitive information, impersonate the user's
identity, or inject malicious content into the victim's web browser.

Note that GizaNE has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://www.phpmyadmin.net/security/PMASA-2019-4/
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 4.9.0 or later.
Alternatively, apply the patches referenced in the vendor advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12616");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/13");

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
include('http.inc');
include('vcf.inc');

port = get_http_port(default:80, php:TRUE);
appname = 'phpMyAdmin';
app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);

constraints = [{'min_version':'4.0', 'fixed_version':'4.9.0'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xsrf:TRUE});
