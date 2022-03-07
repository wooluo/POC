#
# 
#

include("compat.inc");

if (description)
{
  script_id(106375);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/04 15:09:33");

  script_name(english:"nginx HTTP Server Detection");
  script_summary(english:"Detects the nginx HTTP server");

  script_set_attribute(attribute:"synopsis", value:
"The nginx HTTP server was detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to detect the nginx HTTP server by looking at
the HTTP banner on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://nginx.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:igor_sysoev:nginx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/nginx");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

get_kb_item_or_exit("www/nginx");

appname = 'nginx';
port = get_http_port(default:80);
banner = get_http_banner(port:port, exit_on_fail:TRUE);

matches = pregmatch(pattern:"Server: nginx/?([0-9\.]+)? ?(?:\(([a-zA-Z-0-9]+)\))?", string:banner);
if (empty_or_null(matches))
{
  audit(AUDIT_WRONG_WEB_SERVER, port, appname);
}

version = NULL;
extra_array = make_array("source", matches[0]);

if (!empty_or_null(matches[1]))
{
  version = matches[1];
  if (!empty_or_null(matches[2]))
  {
    extra_array["os"] = matches[2];
  }
}

register_install(
    app_name:appname,
    path:'/',
    version:version,
    port:port,
    extra:extra_array,
    webapp:TRUE,
    cpe: "cpe:/a:igor_sysoev:nginx");

report_installs(app_name:appname, port:port);
