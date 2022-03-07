include("compat.inc");


if (description)
{
  script_id(51799308);
  script_version("1.3");
  script_name(english:"Apache Tomcat sample directory session manipulation vulnerability");
  script_summary(english:"Apache Tomcat sample directory session manipulation vulnerability");
  script_set_attribute(attribute:"description", value:"Apache Tomcat sample directory session manipulation vulnerability.");
  script_set_attribute(attribute:"solution", value:"Apache Tomcat sample directory session manipulation vulnerability");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_dependencies("tomcat_error_version.nasl");
  script_require_keys("Services/www");
  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_keepalive.inc");
include("openvas-https2.inc");
include("http_func.inc");

port = get_kb_item("Services/www");
soc = open_sock_tcp(port);
if (!soc)
{
  audit(AUDIT_SOCK_FAIL, port, appname);
}
if (get_kb_list("SSL/Transport/"+port)){
	req = http_get(item:"/examples/servlets/servlet/SessionExample", port:port);
	ssl_reqs = https_req_get(request:req, port:port);
	if('"../sessions.html"' >< ssl_reqs && 'action="SessionExample' >< ssl_reqs){
		security_hole(port:port, extra:"Find Url :/examples/servlets/servlet/SessionExample");
	}
}
else{
	res = http_get(item:"/examples/servlets/servlet/SessionExample", port:port);
	ssl_ress = http_keepalive_send_recv(port:port, data:res, bodyonly:FALSE);
	if('"../sessions.html"' >< ssl_ress && 'action="SessionExample' >< ssl_ress){
		security_hole(port:port, extra:"Find Url :/examples/servlets/servlet/SessionExample");
	}

}
close(soc);
