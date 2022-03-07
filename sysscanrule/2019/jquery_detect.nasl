#
# 
#

include("compat.inc");

if (description)
{
  script_id(106658);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/23 12:57:51");

  script_name(english:"JQuery Detection");
  script_summary(english:"Detects JQuery usage");

  script_set_attribute(attribute:"synopsis", value:
"The web server on the remote host uses JQuery.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to detect JQuery on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://jquery.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

function normalize_path(port, url)
{
  url = build_url(port:port, qs:url);
  var fields = split_url(url:url);
  return normalize_url_path(url:fields["page"]);
}

appname = 'jquery';
port = get_http_port(default:80);
res = http_send_recv3(method:"GET", port:port, item:'/', follow_redirect:3, exit_on_fail:TRUE);
if (empty_or_null(res) || "200 OK" >!< res[0] || empty_or_null(res[2]))
{
  audit(AUDIT_NOT_DETECT, appname, port);
}

# we are just gonna generically scan for jquery script inclusion
# <script src="/javascript/jquery-1.6.2.js" type="text/javascript"></script>
# <script src="./js/jquery/jquery-1.6.2.js?ts=1348024166" type="text/javascript"></script>
matches = pregmatch(string:res[2], pattern:'src=["\']([^ ]+jquery-([0-9\\.]+)(?:\\.min|\\.slim|\\.slim\\.min)*\\.js[^"]*)["\']');
if (!empty_or_null(matches))
{
  # If the js src is hosted elsewhere (a http or https URL) and it
  # is not just an absolute link to this host IP then don't continue
  if (stridx(matches[1], "http") == 0 && get_host_ip() >!< matches[1])
  {
    exit(0, "The remote jquery is not hosted on the target.");
  }

  url = normalize_path(port:port, url:matches[1]);
  if (empty_or_null(url))
  {
    exit(1, "Failed to parse the URL: " + matches[1]);
  }

  register_install(
      app_name:appname,
      path:url,
      version:matches[2],
      port:port,
      webapp:TRUE,
      cpe: "cpe:/a:jquery:jquery");
  report_installs(app_name:appname, port:port);
  exit(0);
}

# look for jquery min, slim, or slim.min
# <script type="text/javascript" src="js/jquery.min.js"></script>
matches = pregmatch(string:res[2], pattern:'src=["\']([^ ]+jquery\\.(?:min|slim|slim\\.min)\\.js)["\']');
if (empty_or_null(matches))
{
  audit(AUDIT_NOT_DETECT, appname, port);
}

# If the js src is hosted elsewhere then don't continue
if (stridx(matches[1], "http") == 0)
{
  exit(0, "The remote jquery is not hosted on the target.");
}

url = normalize_path(port:port, url:matches[1]);
res = http_send_recv3(method:"GET", port:port, item:url, exit_on_fail:TRUE);
if (empty_or_null(res) || "200 OK" >!< res[0] || empty_or_null(res[2]))
{
  audit(AUDIT_NOT_DETECT, appname, port);
}

# jQuery v2.0.1
matches = pregmatch(string:res[2], pattern:'jQuery v([0-9\\.]+)');
if (empty_or_null(matches))
{
  audit(AUDIT_NOT_DETECT, appname, port);
}

register_install(
    app_name:appname,
    path:url,
    version:matches[1],
    port:port,
    webapp:TRUE,
    cpe: "cpe:/a:jquery:jquery");
report_installs(app_name:appname, port:port);
