############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799027);
 name = "Android common component android_ip_webcam of Webcam - unauthorized access";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"Medium");
 script_set_attribute(attribute:"description", value:"There is unauthorized access to the Android common component android_ip_webcam of the webcam, so that anyone can enter the background management page to view the monitoring content, which violates the user's privacy security.");
 script_set_attribute(attribute:"solution", value:"1. Limited directory. 2. The white list restricts the readable path. 3. Set more than 8-digit passwords for components, preferably including upper and lower case letters, numbers, special characters, etc.");
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
	url = string("/shot.jpg?rnd=654321");
	req = http_send_recv3(method: "GET", port: port, item: url);
	if( req[2] == NULL) exit(0);
	con = url + req[1] + req[2];
	if( "200 ">< req[0] && "56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz" >< req[2] ){
	  	if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	url = string("/shot.jpg?rnd=654321");
	res = http_send_recv3(method: "GET", port: port, item: url);
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( "200 "><ssl_req && "56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz"><ssl_req ){
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