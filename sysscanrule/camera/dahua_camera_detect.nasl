include("compat.inc");


if (description)
{
  script_id(51799274);
  script_version("1.3");
  script_name(english:"Dahua camera detect");
  script_summary(english:"Dahua camera detect");
  script_set_attribute(attribute:"description", value:"Dahua camera datect.");
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
	url_ipc = string('/cap.js');
	url_nvr = string('/web_caps/webCapsConfig?version=2');
	req = http_send_recv3(method: "GET", port: port, item: url_ipc,exit_on_fail:0);
	if("200 O">< req[0] && "var devType=" >< req[2] && "var capTcpPort" >< req[2]){
		p = eregmatch(pattern: "var devType='(.*)'", string: req[2], icase: 0);
		if(!isnull(p[1])){
			set_kb_item(name:"Dahua_camrea",value:p[1]);
			security_hole(port:port, data:"Dahua CAMREA " + p[1]);
		}else{
			security_hole(port:port, data:"Dahua CAMREA ");
		}
    }
	if("200 O">!< req[0]){
		req_nvr = http_send_recv3(method: "GET", port: port, item: url_nvr,exit_on_fail:0);
		if("200 O">< req_nvr[0] &&'"deviceType"' >< req_nvr[2] && '"PluginVersion" :' >< req_nvr[2]){
			deviceType = json_read(req_nvr[2]);
			devtype = deviceType['deviceType'];
			if(!isnull(devtype)){
				set_kb_item(name:"Dahua_camrea",value:devtype);
				security_hole(port:port, data:"Dahua CAMREA " + devtype);	
			}
			else{
				security_hole(port:port, data:"Dahua CAMREA ");
			}
		}
	}
}

function check_vuln_ssl(port){
	urls = make_list('/cap.js','/web_caps/webCapsConfig?version=2');
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
		if("200 O"><ssl_req && "var devType=" >< ssl_req && "var capTcpPort" >< ssl_req){
			p = eregmatch(pattern: "var devType='(.*)'" , string: ssl_req, icase: 0);
			if(!isnull(p[1])){
				set_kb_item(name:"Dahua_camrea",value:p[1]);
				security_hole(port:port, data:"HUAWEI CAMREA " + p[1]);
			}
			else{
				security_hole(port:port, data:"Dahua CAMREA ");
			}
		
		}
		if("200 O"><ssl_req && '"deviceType"' >< ssl_req && '"PluginVersion" :' >< ssl_req){
			p = eregmatch(pattern: '{.*}', string: ssl_req, icase: 0);
			deviceType = json_read(req_nvr[2]);
			devtype = deviceType['deviceType'];
			if(!isnull(devtype)){
				set_kb_item(name:"Dahua_camrea",value:devtype);
				security_hole(port:port, data:"Dahua CAMREA " + devtype);	
			}
			else{
				security_hole(port:port, data:"Dahua CAMREA ");
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
