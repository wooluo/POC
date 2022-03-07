############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799088);
 name = "Intellio camera - default password";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"description", value:"Intellio camera default password.");
 script_set_attribute(attribute:"solution", value:"Modify default password.");
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
	host = get_host_name( ); 		
	req1 = 'GET /authorize?user=admin&password=admin HTTP/1.1\r\n' +
			  'Host: ' + host + '\r\n' +
			  'Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n' +
			  'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0)\r\n' +
			  'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
			  'Connection: close\r\n' +
			  'Referer: http://' + host + '/\r\n' +
			  'Upgrade-Insecure-Requests: 1\r\n\r\n';
	req2 = 'POST /login HTTP/1.1\r\n' +
			  'Host: ' + host + '\r\n' +
			  'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0)\r\n' +
			  'Accept: application/json, text/javascript, */*; q=0.01\r\n' +
			  'Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n' +
			  'Connection: close\r\n' +
			  'Referer: http://' + host + '/\r\n' +
			  'Content-Length: 35\r\n\r\n' +
			  '{"User":"admin","Password":"admin"}\r\n';
	buf1 = http_keepalive_send_recv(port:port,data:req1,bodyonly:FALSE);
	buf2 = http_send_recv(port:port, data:req2);

	if( buf1 == NULL && buf2 == NULL ) exit(0);
	con = req1 + buf1 + req2 + buf2;
	if( ("302"><buf1 && "Set-Cookie: user=admin"><buf1 && "Set-Cookie: session="><buf1) || ("200 O"><buf2 && '"sid" :'><buf2 ) ){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
	host = get_host_name( ); 		
	req1 = 'GET /authorize?user=admin&password=admin HTTP/1.1\r\n' +
			  'Host: ' + host + '\r\n' +
			  'Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n' +
			  'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0)\r\n' +
			  'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
			  'Connection: close\r\n' +
			  'Referer: https://' + host + '/\r\n' +
			  'Upgrade-Insecure-Requests: 1\r\n\r\n';
	req2 = 'POST /login HTTP/1.1\r\n' +
			  'Host: ' + host + '\r\n' +
			  'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0)\r\n' +
			  'Accept: application/json, text/javascript, */*; q=0.01\r\n' +
			  'Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n' +
			  'Connection: close\r\n' +
			  'Referer: https://' + host + '/\r\n' +
			  'Content-Length: 35\r\n\r\n' +
			  '{"User":"admin","Password":"admin"}\r\n';
    
	ssl_req1 = https_req_get(port:port,request:req1);
	ssl_req2 = https_req_get(port:port,request:req2);
	if( ssl_req1 == NULL && ssl_req2 == NULL) exit(0);
	con = req1 + ssl_req1 + req2 + ssl_req2;
	if( ("302"><ssl_req1 && "Set-Cookie: user=admin"><ssl_req1 && "Set-Cookie: session="><ssl_req1) || ("200 O"><ssl_req2 && '"sid" :'><ssl_req2 ) ){
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
