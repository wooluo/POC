############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799079);
 name = "Mobotix camera userimage.html - unauthorized access vulnerability";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"Medium");
 script_set_attribute(attribute:"description", value:"Mobotix camera /control/userimage.html file does not have an authorized access vulnerability, resulting in the camera being maliciously monitored and controlled by a third party.");
 script_set_attribute(attribute:"solution", value:"It is recommended to add a password to the camera management page and make requirements for the password strength. Do not face the camera to the privacy room.");
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
	url = string("/control/userimage.html");
	req = http_send_recv3(method: "GET", port: port, item: url);
	con = url + req[2];
	if( "200 O">< req[0] && "Admin Menu" >< req[2] && 'location.href="/control/userimage.html"' >< req[2] && "Zoom" >< req[2] ){
	  	if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	url = string("/control/userimage.html");
	res = http_send_recv3(method: "GET", port: port, item: url);
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if("200 O"><ssl_req && "Admin Menu"><ssl_req && 'location.href="/control/userimage.html"'><ssl_req && "Zoom"><ssl_req){
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
