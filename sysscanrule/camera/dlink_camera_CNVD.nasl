include("compat.inc");


if (description)
{
  script_id(51799275);
  script_version("1.3");
  script_name(english:"Dahua camera CNVD-2020-02465");
  script_summary(english:"Dahua camera CNVD-2020-02465");
  script_set_attribute(attribute:"description", value:"Dahua camera CNVD-2020-02465.");
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
	req = http_send_recv3(method: "GET", port: port, item:"/",exit_on_fail:0);
	if("401">< req[0]){
		p = eregmatch(pattern: 'WWW-Authenticate: Basic realm="(.*)"', string: req[1], icase: 0);
		if(isnull(p[1])) exit(0);
		if ("DCS-935L" >< p[1] || "DCS-960L" >< p[1]) {
			security_hole(port:port, data:"D-Link Vuln  " + p[1]);
		}
    }
}

function check_vuln_ssl(port){
		var req =
		'GET / HTTP/1.1\r\n' +
		'Host: ' + get_host_ip()+':'+ port+ '\r\n' +
		'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0' + '\r\n' +
		'Accept-Encoding: gzip, deflate' + '\r\n' +
		'Connection: keep-alive'+ '\r\n' +
		'Accept: */*' + '\r\n' + 
		'\r\n';
		ssl_req = https_req_get(port:port , request:req);
		if("401"><ssl_req ){
			p = eregmatch(pattern: 'WWW-Authenticate: Basic realm="(.*)"', string: ssl_req, icase: 0);
			if(isnull(p[1])) exit(0);
			if ("DCS-935L" >< p[1] || "DCS-960L" >< p[1]) {
				security_hole(port:port, data:"D-Link Vuln  " + p[1]);
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
