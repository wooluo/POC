include("compat.inc");

if (description)
{
 script_id(51799356);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");


 script_name(english:"jetty HTTP Server Detection");
  script_summary(english:"Detects the jetty HTTP server");

  script_set_attribute(attribute:"synopsis", value:
"The jetty HTTP server was detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to detect the jetty HTTP server by looking at
the HTTP banner on the remote host.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:eclipse:jetty");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
 
 
 
 script_copyright(english:"This script is Copyright (C) 2005-2020 Westpoint Limited");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/nginx");
 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, embedded:TRUE);

if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if("Jetty(" >< banner || "Jetty/" >< banner){
	serv = strstr(banner, "Server");
	matches = eregmatch(pattern:"Jetty(\(|/)([\d\w\.]+)", string:serv);
	
	if (empty_or_null(matches))
	{
	  audit(AUDIT_WRONG_WEB_SERVER, port, appname);
	}

	version = NULL;
	extra_array = make_array("source", matches[0]);
	if (!empty_or_null(matches[2]))
	{
	  version = matches[2];
	}
	register_install(app_name:"jetty",path:'/',version:version,port:port,extra:extra_array,webapp:TRUE,cpe: "cpe:/a:eclipse:jetty");
	report_installs(app_name:appname, port:port);
 }
}
