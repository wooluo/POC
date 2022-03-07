##
# 
##

include('compat.inc');

if (description)
{
  script_id(56509);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/19");

  script_name(english:"ManageEngine ADSelfService Plus Detection");

  script_set_attribute(attribute:"synopsis", value:
"A help desk management application is running on the remote web
server.");
  script_set_attribute(attribute:"description", value:
"ManageEngine ADSelfService Plus, a web-based self-service password
management application written in Java, is running on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.manageengine.com/products/self-service-password/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_adselfservice_plus");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8888);

  exit(0);
}

include('http.inc');
include('install_func.inc');
include('json.inc');
include('debug.inc');

var app, build, extra_nr, json, port, res, url, version;

app = 'ManageEngine ADSelfService Plus';
url = '/servlet/GetProductVersion';
port = get_http_port(default:8888);

res = http_send_recv3(port:port, method:'POST', item:url, exit_on_fail:TRUE);
dbg::log(msg:res[0] + res[1], ddata:res[2]);

if (! empty_or_null(res[2])
  && ! empty_or_null((json = json_read(res[2])))
  && ! empty_or_null(json[0])
  && json[0].PRODUCT_NAME == 'ManageEngine ADSelfService Plus')
{
  version = json[0].PRODUCT_VERSION;
  build   = json[0].BUILD_NUMBER;

  # Save short product version (i.e., 6.1) to KB
  extra_nr.ProductVersion = version;

  register_install(
    app_name  : app,
    port      : port,
    path      : '/',
    # For ADSSP, the build number alone may be enough
    # to distinguish between two releases.
    # Use build for version.
    version   : build,
    extra_no_report : extra_nr,
    display_version : version + ', Build ' + build,
    webapp    : TRUE,
    cpe       : 'cpe:/a:zohocorp:manageengine_adselfservice_plus'
  );

  report_installs(
    app_name  : app,
    port      : port
  );
}
else audit(AUDIT_NOT_DETECT, app, port);
