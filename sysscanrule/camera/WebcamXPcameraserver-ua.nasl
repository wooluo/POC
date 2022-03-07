############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799033);
 name = "WebcamXP camera server - unauthorized access";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_set_attribute(attribute:"risk_factor", value:"Medium");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"description", value:"The windows webcam and IP camera server WebcamXP have unauthorized access vulnerabilities, which cause the camera password to be invalid, the camera security measures to be invalid, and the user's privacy to be disclosed. Use this path to get real-time camera content. Most of them are domestic cameras.");
 script_set_attribute(attribute:"solution", value:"First, don't use the original preset or too simple password. Second, the camera should not be facing the suspected areas such as the bedroom and bathroom. Third, check the camera's angle frequently to see if there is any change. Fourth, develop a good habit of regularly killing viruses.");
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
	url = string("/");
	req = http_send_recv3(method: "GET", port: port, item: url);
	if( req[2] == NULL) exit(0);
	if( "200">< req[0] && (('onchange="CamSelect' >< req[2] && 'onchange="ModeSelect' >< req[2]) || '<a href="javascript:ChangeCam' >< req[2] || ('onchange="ChangeCam' >< req[2] && 'onchange="ChangeMode' >< req[2])) ){
	  	if (report_verbosity > 0) security_hole(port:port, extra:req[2]);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	url = string("/");
	res = http_send_recv3(method: "GET", port: port, item: url);
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( "200 "><ssl_req && (('onchange="CamSelect' >< ssl_req && 'onchange="ModeSelect' >< ssl_req) || '<a href="javascript:ChangeCam' >< ssl_req|| ('onchange="ChangeCam' >< ssl_req && 'onchange="ChangeMode' >< ssl_req)) ){
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
