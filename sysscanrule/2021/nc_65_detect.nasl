include("compat.inc");
if (description)
{
  script_id(51799351);
  script_version("1.3");
  script_name(english:"UFIDA NC is detected to be running");
  script_summary(english:"UFIDA NC is detected to be running");
  script_set_attribute(attribute:"description", value:"UFIDA NC is detected to be running.");
  script_set_attribute(attribute:"solution", value:"update system");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"None");
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
	url = "/Tree.js";
	
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
		if (( "200 OK" >< ssl_reqs || "304 Not Modified" >< ssl_reqs ) && "function LoadTree(vals)" >< ssl_reqs && "IMG SRC='/help/image/message.gif'" >< ssl_reqs){
			report = "UFIDA NC is detected to be running";
			set_kb_item(name:"Services/nc" , value:port);
			set_kb_item(name:"Services/nc/ssl" , value:1);
			return {'vuln':true, 'report':report};
		}
	}
	else{
		res_send = http_send_recv3(method: "GET",port: port, item: url,add_headers: make_array("Content-Type","application/x-www-form-urlencoded"));
		if("function LoadTree(vals)" >< res_send[2] && "IMG SRC='/help/image/message.gif'" >< res_send[2] && ("200 OK" >< res_send[0] || "304 Not Modified" >< res_send[0])){
			report = "UFIDA NC is detected to be running";
			set_kb_item(name:"Services/nc" , value:port);
			set_kb_item(name:"Services/nc/ssl" , value:0);
			return {'vuln':true, 'report':report};
		}

	}
}
