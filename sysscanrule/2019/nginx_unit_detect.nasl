#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124336);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/04 15:09:33");

  script_name(english:"NGINX Unit HTTP Server Detection");
  script_summary(english:"Detects the NGINX Unit HTTP server");

  script_set_attribute(attribute:"synopsis", value:
"The NGINX Unit HTTP server was detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"GizaNE was able to detect the NGINX Unit HTTP server by looking at
the HTTP banner on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://unit.nginx.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nginx:unit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/nginx_unit");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

get_kb_item_or_exit("www/nginx_unit");

appname = 'NGINX Unit';
port = get_http_port(default:80);
banner = get_http_banner(port:port, exit_on_fail:TRUE);

matches = pregmatch(pattern:"Server: Unit/([0-9\.]+)", string:banner);
if (empty_or_null(matches) || empty_or_null(matches[1]))
{
  audit(AUDIT_WRONG_WEB_SERVER, port, appname);
}

version = matches[1];

register_install(
    app_name:appname,
    path:'/',
    version:version,
    port:port,
    webapp:TRUE,
    cpe: "cpe:/a:nginx:unit");

report_installs(app_name:appname, port:port);
