############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799067);
 name = "NUUO-NVR Video storage management system - default password";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"description", value:"There is an arbitrary file download vulnerability in fileread file filepath parameter of intellinet NFC series camera. With a weak password vulnerability, arbitrary files of the system can be downloaded, threatening the security of the server.");
 script_set_attribute(attribute:"solution", value:"1. Limited directory. 2. The white list restricts the readable path.");
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
	url = string("/");
	req1 = http_get(item:url, port:port);
	buf1 = http_keepalive_send_recv(port:port,data:req1,bodyonly:FALSE);
	mat = eregmatch(string: buf1, pattern: "Set-Cookie:.*PHPSESSID=([0-9a-zA-Z]+);",icase:TRUE);
	cookie = mat[1];

	req = 'POST /login.php HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
	  'Connection: close\r\n' +
      'Cookie: PHPSESSID=' + cookie + '; lang=en\r\n' +
      'Content-Length: 46\r\n\r\n' +
	  'language=en&user=admin&pass=admin&submit=Login\r\n';
     
	buf = http_keepalive_send_recv(port:port,data:req,bodyonly:FALSE);
	if( buf == NULL) exit(0);
	con = req + buf;
	if( "302 Found"><buf && '/setting.php">here<'><buf ){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	host1 = get_host_name( );
	if( port==443 ) host=host1;
    else host = string(host1,":",port);

	url = string("/");
	req1 = http_get(item:url, port:port);
	ssl_req1 = https_req_get(port:port,request:req1);
	mat = eregmatch(string: ssl_req1, pattern: "Set-Cookie:.*PHPSESSID=([0-9a-zA-Z]+);",icase:TRUE);
	cookie = mat[1];

	req = 'POST /login.php HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
	  'Connection: close\r\n' +
      'Cookie: PHPSESSID=' + cookie + '; lang=en\r\n' +
      'Content-Length: 46\r\n\r\n' +
	  'language=en&user=admin&pass=admin&submit=Login\r\n';
    
	ssl_req = https_req_get(port:port,request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( "302 Found"><ssl_req && '/setting.php">here<'><ssl_req ){
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
