############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799072);
 name = "Netwave IP Camera - default password";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"description", value:"The default password of netwave IP camera allows attackers to log in to the background directly through the default password, view camera content, modify camera configuration, even control the entire device, and disclose user privacy.");
 script_set_attribute(attribute:"solution", value:"Change password, preferably including upper and lower case letters, numbers and special characters, and the number of digits is greater than 8.");
 script_end_attributes();
 script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("misc_func.inc");
include("openvas-https.inc");


function check_vuln(port){
	if ( !get_port_state(port) ) exit(0);
	host1 = get_host_name( );
	if( port==80 ) host=host1;
    else host = string(host1,":",port);

	req1 = 'GET / HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
	  'Connection: close\r\n' +
      'Authorization: Basic YWRtaW46YWRtaW4=\r\n' +
      'Upgrade-Insecure-Requests: 1\r\n\r\n';
    req2 = 'GET /get_status.cgi?user=admin&pwd=admin HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
	  'Connection: close\r\n\r\n';
	buf1 = http_keepalive_send_recv(port:port,data:req1,bodyonly:FALSE);
	buf2 = http_keepalive_send_recv(port:port,data:req2,bodyonly:FALSE);
	if( buf1 == NULL && buf2 == NULL ) exit(0);
	con = req1 + buf1 + req2 + buf2;
	if( ("200 "><buf1 && "var user;" >< buf1 && "var pwd;" >< buf1 && ' src="get_status.cgi' >< buf1 && '<frame name="vars" src="vars.htm' >< buf1) || ("200 "><buf2 && "Netwave IP Camera" >< buf2 && "var id=" >< buf2 && "var sys_ver=" >< buf2 && "var app_ver=" >< buf2) ){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	host1 = get_host_name( );
	if( port==443 ) host=host1;
    else host = string(host1,":",port);

	req1 = 'GET / HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
	  'Connection: close\r\n' +
      'Authorization: Basic YWRtaW46YWRtaW4=\r\n' +
      'Upgrade-Insecure-Requests: 1\r\n\r\n';
    req2 = 'GET /get_status.cgi?user=admin&pwd=admin HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
	  'Connection: close\r\n\r\n';
    
	ssl_req1 = https_req_get(port:port,request:req1);
	ssl_req2 = https_req_get(port:port,request:req2);
	if( ssl_req1 == NULL && ssl_req2 == NULL) exit(0);
	con = req1 + ssl_req1 + req2 + ssl_req2;
	if( ("200 "><ssl_req1 && "var user;" >< ssl_req1 && "var pwd;" >< ssl_req1 && ' src="get_status.cgi' >< ssl_req1 && '<frame name="vars" src="vars.htm' >< ssl_req1) || ("200 "><ssl_req2 && "Netwave IP Camera" >< ssl_req2 && "var id=" >< ssl_req2 && "var sys_ver=" >< ssl_req2 && "var app_ver=" >< ssl_req2) ){
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
