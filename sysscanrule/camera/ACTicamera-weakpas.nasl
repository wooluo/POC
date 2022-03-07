############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799028);
 name = "ACTi Camera - weak password";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"description", value:"ACTi Camera weak password.");
 script_set_attribute(attribute:"solution", value:"1. Upgrade firmware. 2. Offline from the public network.");
 script_end_attributes();
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
	
	req = 'GET /cgi-bin/system?USER=admin&PWD=123456&LOGIN&SYSTEM_INFO HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
      'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
	  'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
	  'Pragma: no-cache\r\n' +
	  'Cache-Control: no-cache\r\n' +
	  'Expires: 0\r\n' +
	  'Last-Modified: Wed, 1 Jan 1997 00:00:00 GMT\r\n' +
	  'If-Modified-Since: -1\r\n' +
	  'Connection: close\r\n' +
	  'Referer: http://' + host + '/login.html\r\n' +
      'Cookie: User=; Pwd=\r\n\r\n';
     
	buf = http_keepalive_send_recv(port:port,data:req,bodyonly:FALSE);
	if( buf == NULL) exit(0);
	con = req + buf;
	if( "200 "><buf && "Firmware Version"><buf && "LOGIN='"><buf ){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	host1 = get_host_name( );
	if( port==443 ) host=host1;
    else host = string(host1,":",port);

	req = 'GET /cgi-bin/system?USER=admin&PWD=123456&LOGIN&SYSTEM_INFO HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
      'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
	  'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
	  'Pragma: no-cache\r\n' +
	  'Cache-Control: no-cache\r\n' +
	  'Expires: 0\r\n' +
	  'Last-Modified: Wed, 1 Jan 1997 00:00:00 GMT\r\n' +
	  'If-Modified-Since: -1\r\n' +
	  'Connection: close\r\n' +
	  'Referer: https://' + host + '/login.html\r\n' +
      'Cookie: User=; Pwd=\r\n\r\n';
    
	ssl_req = https_req_get(port:port,request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( "200 "><ssl_req && "Firmware Version"><ssl_req && "LOGIN='"><ssl_req ){
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
