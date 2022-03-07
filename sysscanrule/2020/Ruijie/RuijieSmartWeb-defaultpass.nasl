############################################################
# Author: shiyunshu
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799201);
 name = "Ruijie SmartWeb - default password";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family("CNLocal");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"Medium");
 script_set_attribute(attribute:"description", value:"The default passwords of Ruijie SmartWeb can be used by attackers to log into the background directly and control the whole device.");
 script_set_attribute(attribute:"solution", value:"Change password, preferably including upper and lower case letters, numbers and special characters, and the number of digits is greater than 8.");
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
	url = string("/ac/main.htm");
	req = http_send_recv3(method: "GET", port: port, item: url,  add_headers: make_array("User_Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0","Cookie", "menuURL=index; lan=zh; auth=Z3Vlc3Q6Z3Vlc3Q%3D; pass=guest; user=guest; login=1; subMenuId=0" ));
	if( req[2] == NULL) exit(0);
	con = url + req[1] + req[2];
	if( "200 ">< req[0] && ".rui-menu{width:170px; background:url(../images/leftmenu_bg.gif)" >< req[2] && ".rui-menu-head-open{background:url(../images/leftmenu_bg.gif)" >< req[2] ){
	  	if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	url = string("/ac/main.htm");
	res = http_send_recv3(method: "GET", port: port, item: url,  add_headers: make_array("User_Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0","Cookie", "menuURL=index; lan=zh; auth=Z3Vlc3Q6Z3Vlc3Q%3D; pass=guest; user=guest; login=1; subMenuId=0" ));
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = url + ssl_req;
	if( "200 O"><ssl_req && ".rui-menu{width:170px; background:url(../images/leftmenu_bg.gif)"><ssl_req && ".rui-menu-head-open{background:url(../images/leftmenu_bg.gif)"><ssl_req){
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