############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799075);
 name = "Multiple cameras - default password login";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"description", value:"Multiple cameras are logged in with default passwords, among which cameras such as install, reecam and foscam can view camera content, modify camera configuration, and even control the entire device to disclose user privacy.");
 script_set_attribute(attribute:"solution", value:"Change password, preferably including upper and lower case letters, numbers and special characters, and the number of digits is greater than 8.");
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
	url = string("/check_user.cgi");
	req = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("Authorization","Basic YWRtaW46YWRtaW4=" ));
	con = url + req[2];
	if( "200 O">< req[0] && "var user=" >< req[2]  && "var pwd=" >< req[2] && "var pri=3" >< req[2]){
	  	if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	url = string("/check_user.cgi");
	res = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("Authorization","Basic YWRtaW46YWRtaW4=" ));
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if("200 O"><ssl_req && "var user="><ssl_req && "var pwd="><ssl_req && "var pri=3"><ssl_req){
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