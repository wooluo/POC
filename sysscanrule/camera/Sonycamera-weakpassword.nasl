############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799058);
 name = "Sony camera - weak password";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"description", value:"SONY camera weak password:admin/admin,admin/123456,admin/123456789,admin/qwerty,admin/111111");
 script_set_attribute(attribute:"solution", value:"Enhanced password");
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
	url = string("/en/l4/index.html");
	passwds = make_list("Basic YWRtaW46YWRtaW4=","Basic YWRtaW46MTIzNDU=","Basic YWRtaW4lM0ExMjM0NTY=","Basic YWRtaW4lM0FhZG1pbg==","Basic YWRtaW4lM0ExMjM0NTY3ODk=","Basic YWRtaW4lM0Fxd2VydHk=","Basic YWRtaW4lM0ExMTExMTE=");
	foreach passwd (passwds){
		  
          req = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("Authorization",passwd ));
		
          if( "200 O" >!< req[0]) continue;
		  con = url + req[2];
		  if("200 O">< req[0] && "ModelName" >< req[2]){
			if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
		  }
	}
}

function check_vuln_ssl(port){
	url = string("/en/l4/index.html");
	res = http_send_recv3(method: "GET" ,item:url, port:port);
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if("200 O"><ssl_req && "ModelName"><ssl_req){
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