############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799118);
 name = "FLIR camera - weak password";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"description", value:"FLIR camera's weak password can cause hackers to log in to the camera at will to view user's privacy.");
 script_set_attribute(attribute:"solution", value:"Increase password complexity, including case, character, number, etc.");
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
	host1 = get_host_name( );
        if( port==80 ) host=host1;
        else host = string(host1,":",port);
	req = 'POST /api/login HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
	  'Connection: close\r\n' +
	  'Origin: http://' + host + '/\r\n' +
      'X-Requested-With: XMLHttpRequest\r\n' +
	  'Referer: http://' + host + '/\r\n' +
      'Content-Length: 46\r\n\r\n' +
	  'username=admin&password=fliradmin&hosttype=fixed\r\n';
     
	buf = http_keepalive_send_recv(port:port,data:req,bodyonly:FALSE);
	if( buf == NULL) exit(0);
	con = req + buf;
	if( "200 O"><buf && "Content-type: application/json"><buf && '{"error":false'><buf){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
	host = get_host_name( );
	if( port==443 ) host=host1;
        else host = string(host1,":",port);
	req = 'POST /api/login HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
	  'Connection: close\r\n' +
	  'Origin: https://' + host + '/\r\n' +
      'X-Requested-With: XMLHttpRequest\r\n' +
	  'Referer: https://' + host + '/\r\n' +
      'Content-Length: 46\r\n\r\n' +
	  'username=admin&password=fliradmin&hosttype=fixed\r\n';
    
	ssl_req = https_req_get(port:port,request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( "200 O"><ssl_req && "Content-type: application/json"><ssl_req && '{"error":false'><ssl_req ){
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
