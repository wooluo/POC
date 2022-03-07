############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799056);
 name = "StarDot Webcam - weak password";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"description", value:"StarDot Webcam weak password : admin/admin, admin/123456, admin/123456789, admin/qwerty, admin/111111.");
 script_set_attribute(attribute:"solution", value:"Modify default password.");
 script_end_attributes();
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
	url = string("/admin.cgi");
	passwds = make_list("Basic YWRtaW46YWRtaW4=","Basic YWRtaW46MTIzNDU2","Basic YWRtaW46MTIzNDU2Nzg5","Basic YWRtaW46cXdlcnR5","Basic YWRtaW46MTExMTEx");
	foreach passwd (passwds){
          req = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Authorization",passwd ));
          if( "200 " >!< req[0]) continue;
		  con = url + req[2];
	      if("200 ">< req[0] && "Live Image Page" >< req[2]){
	  	   if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
        }
	}
}

function check_vuln_ssl(port){
	url = string("/admin.cgi");
	passwds = make_list("Basic YWRtaW46YWRtaW4=","Basic YWRtaW46MTIzNDU2","Basic YWRtaW46MTIzNDU2Nzg5","Basic YWRtaW46cXdlcnR5","Basic YWRtaW46MTExMTEx");
	foreach passwd (passwds){
	    res = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Authorization",passwd ));
		req = http_last_sent_request();
		ssl_req = https_req_get(port:port , request:req);
		if( "200 " >!< ssl_req) continue;
		con = req + ssl_req;
		if("200 "><ssl_req && "Live Image Page" >< ssl_req){
		    if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	    }
	
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