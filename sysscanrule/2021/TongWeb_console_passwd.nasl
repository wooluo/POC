include("compat.inc");
if (description)
{
  script_id(51799349);
  script_version("1.3");
  script_name(english:"Weak Password Vulnerability in TongWeb Application Server console");
  script_summary(english:"Weak Password Vulnerability in TongWeb Application Server console");
  script_set_attribute(attribute:"description", value:"Weak Password Vulnerability in TongWeb Application Server console.");
  script_set_attribute(attribute:"solution", value:"update system");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"CNLocal");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_require_ports("Services/www",9060);
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
	url = "/console/";
	url_login = "/console/j_security_check";
	if (get_kb_list("SSL/Transport/"+port)){
		var req =
				'GET ' + url +' HTTP/1.1\r\n' +
				'Host: ' + get_host_ip()+':'+ port+ '\r\n' +
				'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0' + '\r\n' +
				'Accept-Encoding: gzip, deflate' + '\r\n' +
				'Content-Type: application/x-www-form-urlencoded' + '\r\n' +
				'Connection: keep-alive'+ '\r\n' +
				'Accept: */*' + '\r\n' + 
				'\r\n';
				
		ssl_reqs = https_req_get(request:req, port:port);
		if ("csrftoken" >< ssl_reqs && '"/console/' >< ssl_reqs && "console-" >< ssl_reqs && "200 OK" >< ssl_reqs){
		
			p = eregmatch(pattern: '.*"csrftoken" value="(.*)">', string: ssl_reqs, icase: 0);
			data = 'csrftoken='+p[1]+'&j_username=tB56wbDaxAF3rPJ%2Bi5p9Yg%3D%3D&j_password=vUoiQcOJW4QFf7fSVY45ng%3D%3D';
			
			var res =
				'POST ' + url_login +' HTTP/1.1\r\n' +
				'Host: ' + get_host_ip()+':'+ port+ '\r\n' +
				'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0' + '\r\n' +
				'Accept-Encoding: gzip, deflate' + '\r\n' +
				'Content-Type: application/x-www-form-urlencoded' + '\r\n' +
				'Connection: keep-alive'+ '\r\n' +
				'Accept: */*' + '\r\n' + 
				'\r\n'+data;
			
			ssl_ress = https_req_get(request:res, port:port);
			if("302 Found" >< ssl_ress && "/console/" >< ssl_ress && "j_security_check" >!< ssl_ress && "TongWeb" >< ssl_ress){
				report = "thanos:thanos123.com";
				return {'vuln':true, 'report':report};
			}
		}
	}
	else{
		res_send = http_send_recv3(method: "GET",port: port, item: url,add_headers: make_array("Content-Type","application/x-www-form-urlencoded"));
		if("csrftoken" >< res_send[2]&& '"/console/' >< res_send[2] && "console-" >< res_send[1] && "200 OK" >< res_send[0]){
			
			p = eregmatch(pattern: '.*"csrftoken" value="(.*)">', string: res_send[2], icase: 0);
			data = 'csrftoken='+p[1]+'&j_username=tB56wbDaxAF3rPJ%2Bi5p9Yg%3D%3D&j_password=vUoiQcOJW4QFf7fSVY45ng%3D%3D';
	
			resp = http_send_recv3(method: "POST",port: port, item: url_login, data:data, add_headers: make_array("Content-Type","application/x-www-form-urlencoded"));
			if("302 Found" >< resp[0] && "/console/" >< resp[1] && "j_security_check" >!< resp[1] && strlen(resp[2])< 2 ){
				report = "thanos:thanos123.com";
				return {'vuln':true, 'report':report};
			}
		}

	}
}
