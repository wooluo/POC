############################################################
include("compat.inc");


if(description)
{
 script_id(51799081);
 name = "MasterIPCAM01 Camera - default account password";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"description", value:"MASTER IPCAMERA01 camera has a default account problem, so the attacker may log in the system through limited blasting, understand and change the network settings, system settings, management information, etc., causing serious information leakage and complete camera equipment.");
 script_set_attribute(attribute:"solution", value:"1. Upgrade the version in time. Website: http://ipcameramaster.com/category/ip-camera-reviews/2. Change the system default weak password, preferably more than 8 digits, including upper and lower case letters, numbers and special characters.");
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
	url = string("/PSIA/System/deviceInfo");
	passwds = make_list("Basic Z3Vlc3Q6Z3Vlc3Q=","Basic YWRtaW46YWRtaW4=","Basic dXNlcjp1c2Vy");
	foreach passwd (passwds){
          req = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("Upgrade-Insecure-Requests", "1","User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Authorization",passwd ));
          if( "200 " >!< req[0]) continue;
		  con = url + req[2];
	      if("200 O">< req[0] && "Welcome" >< req[2] && "<statusValue>200</statusValue>" >< req[2]){
	  	   if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
        }
	}
}

function check_vuln_ssl(port){
	url = string("/PSIA/System/deviceInfo");
	passwds = make_list("Basic Z3Vlc3Q6Z3Vlc3Q=","Basic YWRtaW46YWRtaW4=","Basic dXNlcjp1c2Vy");
	foreach passwd (passwds){
	    res = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("Upgrade-Insecure-Requests", "1","User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Authorization",passwd ));
		req = http_last_sent_request();
		ssl_req = https_req_get(port:port , request:req);
		if( "200 " >!< ssl_req) continue;
		con = req + ssl_req;
		if("200 O"><ssl_req && "Welcome" >< ssl_req && "<statusValue>200</statusValue>" >< ssl_req){
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
