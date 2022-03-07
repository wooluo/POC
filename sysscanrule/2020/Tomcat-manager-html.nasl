############################################################
# Author: shiyunshu
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799238);
 name = "Tomcat found the default file /manager/html/";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Web Servers");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"Low");  
 script_set_attribute(attribute:"description", value:"Tomcat found the default file /manager/html/.");
 script_set_attribute(attribute:"solution", value:"Please delete the file.");
 script_end_attributes();
 script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
 script_require_ports("Services/www", 8080);
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
	url = string("/manager/html/");
	req = http_send_recv3(method: "GET", port: port, item: url);
	if( req[2] == NULL) exit(0);
	if( "401 ">< req[0] && "For example, to add the <tt>manager-gui</tt> role to a user named" >< req[2] && "<tt>tomcat</tt> with a password of" >< req[2]){
	  	if (report_verbosity > 0) security_hole(port:port, extra:req[2]);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	url = string("/manager/html/");
	res = http_send_recv3(method: "GET", port: port, item: url);
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( "401 "><ssl_req && "For example, to add the <tt>manager-gui</tt> role to a user named" ><ssl_req && "<tt>tomcat</tt> with a password of"><ssl_req ){
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