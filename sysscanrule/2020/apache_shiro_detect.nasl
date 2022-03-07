include("compat.inc");


if (description)
{
  script_id(51799293);
  script_version("1.3");
  script_name(english:"Apache Shiro detect");
  script_summary(english:"Apache Shiro detect");
  script_set_attribute(attribute:"description", value:"Apache Shiro detect.");
  script_set_attribute(attribute:"solution", value:"Apache Shiro detect");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  
  script_require_ports("Services/www", 80);
  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");
include("install_func.inc");
include("dump.inc");
#include("int2hex.inc");

port = get_kb_item("Services/www");

headers = make_array("Cookie", "rememberMe=Test_Shiro");

soc = open_sock_tcp(port);
if (!soc)
{
  audit(AUDIT_SOCK_FAIL, port, appname);
}
if (get_kb_list("SSL/Transport/"+port)){
	fast_send1 = http_send_recv3(method: "GET", port: port, item: "/login",add_headers: headers);
	reqs = http_last_sent_request();
	ssl_reqs = https_req_get(request:reqs, port:port,recv3:1);
	
}
else{
	fast_send = http_send_recv3(method: "GET", port: port, item: "/login",add_headers: headers);
}
close(soc);
if ((("Set-Cookie: rememberMe" >< ssl_reqs[0] || "rememberMe=deleteMe" >< ssl_reqs[0]) && "Test_Shiro" >!< ssl_reqs[0] ) || ("Set-Cookie: rememberMe" >< fast_send[1] || "rememberMe=deleteMe" >< fast_send[1])){
	set_kb_item(name:"shiro/installed",value:1);
	set_kb_item(name:"shiro/installed/port",value:port);
	security_hole(port:port, extra:"Cookie: rememberMe=Test_Shiro");
} 
