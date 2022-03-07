include("compat.inc");


if (description)
{
  script_id(51799271);
  script_version("1.3");
  script_name(english:"uniview camera detect");
  script_summary(english:"uniview camera detect");
  script_set_attribute(attribute:"description", value:"uniview camera datect.");
  script_set_attribute(attribute:"solution", value:"None");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Camera");
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
include("json.inc");
include("openvas-https2.inc");


function check_vuln(port){
	url_ipc = string('/js/device_type.js');
	url_nvr = string('/cgi-bin/main-cgi?json={"cmd":%20116}');
	req = http_send_recv3(method: "GET", port: port, item: url_ipc,exit_on_fail:0);
	if("200 O">< req[0] && "var showDeviceType" >< req[2] && "var showDeviceName" >< req[2]){
		p = eregmatch(pattern: 'var showDeviceType = "(.*)"', string: req[2], icase: 0);
		set_kb_item(name:"uniview_camrea",value:p[1]);
		security_hole(port:port, data:"UniView CAMREA " + p[1]);

    }
	if("200 O">!< req[0]){
		req_nvr = http_send_recv3(method: "GET", port: port, item: url_nvr,exit_on_fail:0);
		if("200 O">< req_nvr[0] &&'"szhttphost"' >< req_nvr[2] && '"szDeviceName"' >< req_nvr[2]){
			szDeviceName = json_read(req_nvr[2]);
			DeviceName = szDeviceName['szDeviceName'];
			if(!isnull(DeviceName)){
				set_kb_item(name:"uniview_camrea",value:DeviceName);
				security_hole(port:port, data:"UniView CAMREA " + DeviceName);	
			}
		}
	}
}

function check_vuln_ssl(port){
	urls = make_list('/js/device_type.js','/cgi-bin/main-cgi?json={"cmd":%20116}');
	foreach url (urls){
		var req =
		'GET ' + url +' HTTP/1.1\r\n' +
		'Host: ' + get_host_ip()+':'+ port+ '\r\n' +
		'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0' + '\r\n' +
		'Accept-Encoding: gzip, deflate' + '\r\n' +
		'Connection: keep-alive'+ '\r\n' +
		'Accept: */*' + '\r\n' + 
		'\r\n';
		ssl_req = https_req_get(port:port , request:req);
		if("200 O"><ssl_req && "var showDeviceType" >< ssl_req && "var showDeviceName" >< ssl_req){
			p = eregmatch(pattern: 'var showDeviceType = "(.*)"', string: ssl_req, icase: 0);
			set_kb_item(name:"uniview_camrea",value:p[1]);
			security_hole(port:port, data:"UniView CAMREA " + p[1]);
		}
		if("200 O"><ssl_req && '"szhttphost"' >< ssl_req && '"szDeviceName"' >< ssl_req){
			p = eregmatch(pattern: '{.*}', string: ssl_req, icase: 0);
			szDeviceName = json_read(p[0]);
			DeviceName = szDeviceName['szDeviceName'];
			if(!isnull(DeviceName)){
				set_kb_item(name:"uniview_camrea",value:DeviceName);
				security_hole(port:port, data:"UniView CAMREA " + DeviceName);	
			}
		}
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
