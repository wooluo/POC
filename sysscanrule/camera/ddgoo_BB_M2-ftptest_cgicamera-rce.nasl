############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799123);
 name = "ddgoo_BB_M2 ftptest.cgi camera - remote command execution";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"description", value:"set_ftp.cgi is a parameter setting page of FTP service, which is used to set related parameters of FTP service, such as binding IP, FTP username and password, etc. It will write the relevant parameters to the internal variables, and then read the internal variables and write them to /tmp/ftpupload.sh by accessing ftptest.cgi. Because the key characters are not filtered, the shell command can be injected into the script file. Most parameters can be used for injection commands.");
 script_set_attribute(attribute:"solution", value:"Upgrade firmware version.");
 script_end_attributes();
 script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");


function check_vuln(port){
	if ( !get_port_state(port) ) exit(0);
	url = string("/ftptest.cgi?next_url=test_ftp.html&loginuse=admin&loginpas=password");
	req = http_send_recv3(method: "GET", port: port, item: url);
	if( req[2] == NULL) exit(0);
	con = url + req[2];
	if( "200 ">< req[0] && 'var result="Auth Failed";'><req[2] ){
	  	if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	url = string("/ftptest.cgi?next_url=test_ftp.html&loginuse=admin&loginpas=password");
	res = http_send_recv3(method: "GET", port: port, item: url);
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( "200 "><ssl_req && 'var result="Auth Failed";'><ssl_req ){
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
