############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799071);
 name = "NETWAVE webcam get_status.cgi page - sensitive information disclosure";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"Medium");
 script_set_attribute(attribute:"description", value:"NETWAVE IP Camera is a webcam product produced by Dutch NetWave SystemsB.V. company.There is a risk of unauthorized access information disclosure on the NETWAVE IP Camera page get_status.cgi(such as obtaining the MAC address of the device, etc.), which can be used by the attacker to facilitate the next step.");
 script_set_attribute(attribute:"solution", value:"1. Control access to sensitive pages. 2. Update to the latest version. Website: http://www.netwavesystems.com/");
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
	url = string("/get_status.cgi");
	req = http_send_recv3(method: "GET", port: port, item: url);
	con = url + req[2];
	if( "200 O">< req[0] && "var app_ver=" >< req[2] ){
	  	if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	url = string("/get_status.cgi");
	res = http_send_recv3(method: "GET", port: port, item: url);
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if("200 O"><ssl_req && "var app_ver="><ssl_req){
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