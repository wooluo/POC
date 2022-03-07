############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799041);
 name = "VideoIQ-Camera - Weak password";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"description", value:"VideoIQ-Camera weak password.");
 script_set_attribute(attribute:"solution", value:"Increase password strength.");
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
	url1 = string("/");
	req1 = http_get(item:url1, port:port);
	buf1 = http_keepalive_send_recv(port:port,data:req1,bodyonly:FALSE);
	mat = eregmatch(string: buf1, pattern: "Set-Cookie:.*JSESSIONID=([0-9a-zA-Z]+);");
	cookie = mat[1];
	if( cookie == NULL ) exit(0);
	
	req2 = 'POST /;jsessionid=' + cookie + '?wicket:bookmarkablePage=:com.videoiq.fusion.camerawebapi.ui.pages.LoginPage&wicket:interface=:0:loginPanel:loginForm::IFormSubmitListener:: HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
	  'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n' +
	  'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
	  'Content-Length: 63\r\n' +
	  'Origin: http://' + host + '\r\n' +
	  'Connection: close\r\n' +
	  'Referer: http://' + host + '/;jsessionid=' + cookie + '?wicket:bookmarkablePage=:com.videoiq.fusion.camerawebapi.ui.pages.LoginPage\r\n' +
      'Cookie: JSESSIONID=' + cookie + '\r\n' +
      'Upgrade-Insecure-Requests: 1\r\n\r\n' +
	  'loginForm1_hf_0=&userName=supervisor&password=supervisor&login=';
     
	buf2 = http_keepalive_send_recv(port:port,data:req2,bodyonly:FALSE);
	if( "302 Found">!<buf2 ) exit(0);
	url = eregmatch(string: buf2, pattern: "/;([0-9a-zA-Z/.=]+)\r\n"); 
	req = 'GET /;' + url[1] + ' HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
	  'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n' +
	  'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
	  'Origin: http://' + host + '\r\n' +
	  'Connection: close\r\n' +
      'Cookie: JSESSIONID=' + cookie + '\r\n' +
      'Upgrade-Insecure-Requests: 1\r\n\r\n';
	buf = http_keepalive_send_recv(port:port,data:req,bodyonly:FALSE);
	con = req + buf;
	if( '<frame src="/?wicket:bookmarkablePage=:com.videoiq.fusion.camerawebapi.ui.pages.LiveVideoPage" name="main"/>'><buf && "<title>VideoIQ camera</title>"><buf && '<frame src="/?wicket:bookmarkablePage=:com.videoiq.fusion.camerawebapi.ui.pages.MenuPage" name="menu"/>'><buf ){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	host1 = get_host_name( );
	if( port==443 ) host=host1;
    else host = string(host1,":",port);

	url1 = string("/");
	req1 = http_get(item:url1, port:port);
	ssl_req1 = https_req_get(port:port,request:req1);
	mat = eregmatch(string: buf1, pattern: "Set-Cookie:.*JSESSIONID=([0-9a-zA-Z]+);");
	cookie = mat[1];
	if( cookie == NULL ) exit(0);
	
	req2 = 'POST /;jsessionid=' + cookie + '?wicket:bookmarkablePage=:com.videoiq.fusion.camerawebapi.ui.pages.LoginPage&wicket:interface=:0:loginPanel:loginForm::IFormSubmitListener:: HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
	  'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n' +
	  'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
	  'Content-Length: 63\r\n' +
	  'Origin: https://' + host + '\r\n' +
	  'Connection: close\r\n' +
	  'Referer: https://' + host + '/;jsessionid=' + cookie + '?wicket:bookmarkablePage=:com.videoiq.fusion.camerawebapi.ui.pages.LoginPage\r\n' +
      'Cookie: JSESSIONID=' + cookie + '\r\n' +
	  'Upgrade-Insecure-Requests: 1\r\n\r\n' +
	  'loginForm1_hf_0=&userName=supervisor&password=supervisor&login=';
    
	ssl_req2 = https_req_get(port:port,request:req2);
	if( "302 Found">!<ssl_req2) exit(0);
	url = eregmatch(string: ssl_req2, pattern: "/;([0-9a-zA-Z/:.=]+)\r\n"); 
	req = 'GET /;' + url[1] + ' HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
	  'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n' +
	  'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
	  'Origin: https://' + host + '\r\n' +
	  'Connection: close\r\n' +
      'Cookie: JSESSIONID=' + cookie + '\r\n'+
	  'Upgrade-Insecure-Requests: 1\r\n\r\n';
	ssl_req = https_req_get(port:port,request:req);
	con = req + ssl_req;
	if( '<frame src="/?wicket:bookmarkablePage=:com.videoiq.fusion.camerawebapi.ui.pages.LiveVideoPage" name="main"/>'><ssl_req && "<title>VideoIQ camera</title>"><ssl_req && '<frame src="/?wicket:bookmarkablePage=:com.videoiq.fusion.camerawebapi.ui.pages.MenuPage" name="menu"/>'><ssl_req){
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