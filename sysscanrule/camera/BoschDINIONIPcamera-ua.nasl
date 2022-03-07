############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799148);
 name = "Bosch DINION IP Camera - unauthorized access";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"description", value:"Bosch DINION IP camera is not authorized to access the vulnerability. Anyone can visit the background management page to view the camera content directly, which violates the privacy security of the user. It can also modify the configuration and other malicious operations, and even control the entire device, making the device in a state of extreme insecurity.");
 script_set_attribute(attribute:"solution", value:"1. Limited directory. 2. The white list restricts the readable path. 3. Add more than 8 passwords, preferably including upper and lower case letters, numbers and special characters.");
 script_end_attributes();
 script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");


function check_vuln(port){
	if ( !get_port_state(port) ) exit(0);
	url = string("/");
	buf = http_send_recv3(method: "GET", port: port, item: url);
	url1 = string("/view.htm?mode=l");
	buf1 = http_send_recv3(method: "GET", port: port, item: url1);
	url2 = string("/live.htm");
	buf2 = http_send_recv3(method: "GET", port: port, item: url2);
	if( buf1[2] == NULL && buf2[2] == NULL && buf[2] == NULL) exit(0);
	con = url1 + buf1[2] + url2 + buf2[2] + url + buf[2];
	if( ("200 ">< buf1[0] && "videocontainer" >< buf1[2]) || ("200 ">< buf2[0] && "mainFrame" >< buf2[2] && "inner_frmset.html" >< buf2[2]) || ("200 ">< buf[0] && 'document.location.href="upload.htm"' >< buf[2] && "loadxmlfunc(getLang(), setPageTitle" >< buf[2])){
	  	if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	url = string("/");
	req = http_get(item:url, port:port);
	ssl_req = https_req_get(port:port,request:req);
	url1 = string("/view.htm?mode=l");
	req1 = http_get(item:url1, port:port);
	ssl_req1 = https_req_get(port:port,request:req1);
	url2 = string("/live.htm");
	req2 = http_get(item:url2, port:port);
	ssl_req2 = https_req_get(port:port,request:req2);
	if( ssl_req1 == NULL && ssl_req2 == NULL && ssl_req == NULL ) exit(0);
	con = req1 + ssl_req1 + req2 + ssl_req2 + req + ssl_req;
	if( ("200 ">< ssl_req1 && "videocontainer" >< ssl_req1) || ("200 ">< ssl_req2 && "mainFrame" >< ssl_req2 && "inner_frmset.html" >< ssl_req2) || ("200 ">< ssl_req && 'document.location.href="upload.htm"' >< ssl_req && "loadxmlfunc(getLang(), setPageTitle" >< ssl_req)){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

##################################
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
