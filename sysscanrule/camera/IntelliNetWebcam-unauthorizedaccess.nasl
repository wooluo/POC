############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799089);
 name = "IntelliNet Webcam - unauthorized access";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"Medium");
 script_set_attribute(attribute:"description", value:"There is an unauthorized access vulnerability in the intellinet IP camera. Anyone can directly access the background, view the camera status, content and other sensitive information, or even live video content.");
 script_set_attribute(attribute:"solution", value:"1. Limited directory. 2. The white list restricts the readable path. 3. Set the password with more than 8 digits, preferably including upper and lower case letters, numbers and special characters.");
 script_end_attributes();
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
	url = string("/");
	req = http_send_recv3(method: "GET", port: port, item: url);
	if( "200 O">< req[0] && "controlmenu.htm" >< req[2] && "MARGINHEIGHT" >!< req[2] && "mainFrame" >< req[2]){
	  	if (report_verbosity > 0) security_hole(port:port, extra:req[2]);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	url = string("/");
	res = http_send_recv3(method: "GET", port: port, item: url);
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if("200 O"><ssl_req && "controlmenu.htm"><ssl_req && "MARGINHEIGHT">!<ssl_req && "mainFrame"><ssl_req){
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
