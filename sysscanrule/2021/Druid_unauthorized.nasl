include("compat.inc");


if (description)
{
  script_id(51799312);
  script_version("1.3");
  script_name(english:"Druid unauthorized access vulnerability");
  script_summary(english:"Druid unauthorized access vulnerability");
  script_set_attribute(attribute:"description", value:"Druid unauthorized access vulnerability.");
  script_set_attribute(attribute:"solution", value:"Druid unauthorized access vulnerability");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_require_ports("Services/www");
  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");
include("install_func.inc");
include("dump.inc");

port = get_kb_item("Services/www");
soc = open_sock_tcp(port);
if (!soc)
{
  audit(AUDIT_SOCK_FAIL, port, appname);
}
if (get_kb_list("SSL/Transport/"+port)){
	req = http_get(item:"/druid/index.html", port:port);
	ssl_reqs = https_req_get(request:req, port:port);
	if("Druid Stat Index" >< ssl_reqs && "DruidVersion" >< ssl_reqs && "DruidDrivers" >< ssl_reqs && "200 OK" >< ssl_reqs){
		security_hole(port:port, extra:"Druid unauthorized access vulnerability: /druid/index.html");
	}
}
else{
	resp = http_send_recv3(method: "GET", port: port, item: "/druid/index.html");
	if("200 OK" >< resp[0] && "Druid Stat Index" >< resp[2] && "DruidVersion" >< resp[2] && "DruidDrivers" >< resp[2]){
		security_hole(port:port, extra:"Druid unauthorized access vulnerability: /druid/index.html");
	}
}
close(soc);
