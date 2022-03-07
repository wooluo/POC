##
# 
##

include('compat.inc');

if (description)
{
  script_id(51874);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/04");

  script_name(english:"PRTG Network Monitor Detection");
  script_summary(english:"Checks for PRTG Network Monitor");

  script_set_attribute(attribute:"synopsis", value:
"A network traffic monitoring application is hosted on the remote web
server.");

  script_set_attribute(attribute:"description", value:
"PRTG Network Monitor, a web-based tool for displaying network and
bandwidth usage data, is hosted on the remote web server.");

  script_set_attribute(attribute:"see_also", value:"https://www.paessler.com/prtg");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:paessler_ag:prtg_network_monitor");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:paessler:prtg_network_monitor");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_require_keys("www/prtg");

  exit(0);
}

include('http.inc');
include('webapp_func.inc');

app_name = 'prtg_network_monitor';
port = get_http_port(default:80);

version = UNKNOWN_VER;

banner = get_http_banner(port:port, exit_on_fail:TRUE);

headers = parse_http_headers(status_line:banner, headers:banner);
if (isnull(headers))
  exit(1, 'Error processing HTTP response headers from the web server on port '+port+'.');

server = headers['server'];
if (isnull(server))
  exit(0, "The web server on port "+port+" doesn't send a Server response header.");

if ('PRTG' >!< server)
  exit(0, "The web server on port "+port+" doesn't appear to be from PRTG Network Monitor.");


matches = pregmatch(pattern:"PRTG/([0-9.]+)",string:server);
if (matches) version = matches[1];

res = http_send_recv3(method:"GET", item:"/index.htm", port:port, exit_on_fail:TRUE);

if ('PRTG Network Monitor' >< res[2])
{
  register_install(
    app_name : app_name,
    path     : '/index.htm',
    version  : version,
    cpe      : 'cpe:/a:paessler_ag:prtg_network_monitor',
    port     : port,
    webapp   : TRUE
  );
  report_installs(app_name:app_name);
  set_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);
}
else
{
  audit(AUDIT_NOT_DETECT, app_name, port);
}