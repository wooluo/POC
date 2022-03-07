include("compat.inc");


if (description)
{
  script_id(51799303);
  script_version("1.3");
  script_cve_id("CVE-2020-10148");
  script_name(english:"SolarWinds Orion API  RCE");
  script_summary(english:"SolarWinds Orion API  RCE");
  script_set_attribute(attribute:"description", value:"SolarWinds Orion API  RCE.");
  script_set_attribute(attribute:"solution", value:"SolarWinds Orion API  RCE");
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
		res = http_get(item:"/Orion/invalid.aspx.js", port:port);
		ssl_res = https_req_get(request:res, port:port);
		if("404 Not" >< ssl_res && "Location: /Orion/invalid.aspx.js." >< ssl_res){
			uri = eregmatch(pattern:"Location: /Orion/invalid.aspx.js(.*)\r\n", string:ssl_res);
			url = "/web.config"+uri[1];
			req = http_get(item:url, port:port);
			ssl_reqs = https_req_get(request:req, port:port);
			if("SolarWinds.Orion.Core.Common" >< ssl_reqs && "SolarWinds.Orion.Web.LoggingHttp" >< ssl_reqs){
				security_hole(port:port, data:ssl_reqs);
			}	
		}
		
	}else{
		res = http_send_recv3(method: "GET", port: port, item: "/Orion/invalid.aspx.js");
		if("404" >< res[0] && "Location: /Orion/invalid.aspx.js." >< res[1] ){
			uri = eregmatch(pattern:"Location: /Orion/invalid.aspx.js(.*)\r\n", string:res[1]);
			url = "/web.config"+uri[1];
			req = http_send_recv3(method: "GET", port: port, item: url);
			if("200 OK" >< req[0] && "SolarWinds.Orion.Core.Common" >< req[2] && "SolarWinds.Orion.Web.LoggingHttp" >< req[2]){
				security_hole(port:port, extra:req[2]);
			}
		}
	}
	close(soc);
}
