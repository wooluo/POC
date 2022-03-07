############################################################
# Author: shiyunshu
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799232);
 name = "IIS short file name";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Web Servers");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");  
 script_set_attribute(attribute:"description", value:"Windows are generated in 8.3 format compatible with ms-dos (short) of the file name, to allow based on ms-dos or 16-bit Windows applications access these files.");
 script_set_attribute(attribute:"solution", value:"Filter - or the request of the Unicode.");
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
	url = string("/*~1*/a.aspx");
	req = http_send_recv3(method: "GET", port: port, item: url);
	url1 = string("/d1c30y*~1*/.aspx");
	req1 = http_send_recv3(method: "GET", port: port, item: url1);
	if( req[2] == NULL && req1[2] == NULL) exit(0);
	con = req[2] + req1[2];
	if( "404 ">< req[0] && "0x00000000" >< req[2] && "400 " >< req1[0] && "0x80070002" >< req1[2] ){
	  	if (report_verbosity > 0) security_hole(port:port, extra:con );
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	url = string("/*~1*/a.aspx");
	res = http_send_recv3(method: "GET", port: port, item: url);
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	url1 = string("/d1c30y*~1*/.aspx");
	res1 = http_send_recv3(method: "GET", port: port, item: url1);
	req1 = http_last_sent_request();
    ssl_req1 = https_req_get(port:port , request:req1);
	if( ssl_req == NULL && ssl_req1 == NULL ) exit(0);
	con = req + ssl_req + req1 + ssl_req1;
	if( "404 "><ssl_req && "0x00000000"><ssl_req && "400 "><ssl_req1 && "0x80070002"><ssl_req1 ){
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