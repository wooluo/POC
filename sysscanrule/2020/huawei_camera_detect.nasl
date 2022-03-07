include("compat.inc");


if (description)
{
  script_id(51799247);
  script_version("1.3");
  script_name(english:"huawei camera detect");
  script_summary(english:"huawei camera detect");
  script_set_attribute(attribute:"description", value:"huawei camera datect.");
  script_set_attribute(attribute:"solution", value:"None");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Camera");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  exit(0);
}


############################################
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");


function check_vuln(port){
	url = string('/data/ConfigData.js');
	if ("80" == port){
		refer = "http://"+get_host_ip()+"/index.html";
	}
	else{
		refer = "http://"+get_host_ip()+":"+port+"/index.html";
	}
	req = http_send_recv3(method: "GET", port: port, item: url,add_headers: make_array("Referer", refer), exit_on_fail:0);
	if("200 O">< req[0] && "configData_titleName" >< req[2] && "HUAWEI" >< req[2] && "var detailType" ><req[2]){
		p = eregmatch(pattern: 'var detailType = "(.*)"', string: req[2], icase: 0);
		
		set_kb_item(name:"hw_ipc_port",value:port);
		set_kb_item(name:"hw_ipc_ssl",value:0);
		set_kb_item(name:"hw_ipc_refer",value:refer);
		security_hole(port:port, data:"HUAWEI CAMREA " + p[1]);

    }
}

function check_vuln_ssl(port){
	url = string('/data/ConfigData.js');
	if ("443" == port){
		refer = "https://"+get_host_ip()+"/index.html";
	}
	else{
		refer = "https://"+get_host_ip()+":"+port+"/index.html";
	}
	var req =
		'GET ' + url +' HTTP/1.1\r\n' +
		'Host: ' + get_host_ip()+':'+ port+ '\r\n' +
		'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0' + '\r\n' +
		'Accept-Encoding: gzip, deflate' + '\r\n' +
		'Referer: '+refer + '\r\n' +
		'Connection: keep-alive'+ '\r\n' +
		'Accept: */*' + '\r\n' + 
		'\r\n';
	ssl_req = https_req_get(port:port , request:req);
	if("200 O"><ssl_req && "configData_titleName" >< ssl_req && "HUAWEI" >< ssl_req && "var detailType" >< ssl_req){
		p = eregmatch(pattern: 'var detailType = "(.*)"', string: ssl_req, icase: 0);
		
		set_kb_item(name:"hw_ipc_sslport",value:port);
		set_kb_item(name:"hw_ipc_ssl",value:1);
		set_kb_item(name:"hw_ipc_sslrefer",value:refer);
		
		security_hole(port:port, data:"HUAWEI CAMREA " + p[1]);
	}
}


####################
#begin here
####################
kbs = get_kb_list("www/banner/*");
foreach k (keys(kbs)) {
	port = substr(k,11);
	ssl = get_kb_list("SSL/Transport/"+port);
	if(!ssl) {
   		check_vuln(port:port);
	} else {
   		check_vuln_ssl(port:port);
	}

}
exit(0);
