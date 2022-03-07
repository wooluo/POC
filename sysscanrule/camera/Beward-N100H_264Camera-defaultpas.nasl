############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799149);
 name = "Beward-N100 H.264 Camera - default password";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"description", value:"Beward-N100 H.264 camera default password allows the attacker to log into the background directly, view the content of the camera, modify the camera configuration, even control the entire device, and disclose the user's privacy.");
 script_set_attribute(attribute:"solution", value:"Modify the default password, preferably including upper and lower case letters, numbers and special characters, and the number of digits is greater than 8.");
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
	url = string("/");
	req = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("Authorization","Basic YWRtaW46YWRtaW4=" ));
	con = req[0] + req[1] + req[2];
	if( ("200 OK">< req[0] || "200 Ok">< req[0] ) && "./style/image/btn_information_e.png" >< req[2]){
	  	if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	url = string("/");
	res = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("Authorization","Basic YWRtaW46YWRtaW4=" ));
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( ("200 OK"><ssl_req || "200 Ok"><ssl_req )&& "./style/image/btn_information_e.png"><ssl_req){
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