############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY   # http://123.13.218.186:7788/config/user.xml
############################################################
include("compat.inc");

if (description)
{
  script_id(51799105);
  script_version("1.3");
  script_name(english:"Hikvision Streaming media management server Information disclosure");
  script_summary(english:"Hikvision Streaming media management server Information disclosure");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"description", value:"Hikvision Streaming media management server Information disclosure");
  script_set_attribute(attribute:"solution", value:"update system");
  script_set_attribute(attribute:"vuln_publication_date",value:"2018/10/11");
  script_set_attribute(attribute:"patch_publication_date",value:"2018/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/22");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Camera");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_require_ports("Services/www", 80);
  exit(0);
}



include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("misc_func.inc");
include("openvas-https.inc");


function check_vuln(port){
	url = string("/config/user.xml");
	req = http_get(item:url, port:port);
    recv = http_keepalive_send_recv(data:req, port:port, bodyonly:FALSE);
	if( recv == NULL) exit(0);
	if("200 OK"><recv && "text/xml"><recv && 'password="' >< recv){
		if (report_verbosity > 0) security_hole(port:port, extra:req+recv);
	    else security_hole(port);
	}
}

function check_vuln_ssl(port){
	url = string("/config/user.xml");
	req = http_get(item:url, port:port);
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	if("200 OK"><ssl_req && "text/xml"><ssl_req  && 'password="' >< ssl_req ){
		if (report_verbosity > 0) security_hole(port:port, extra:req+ssl_req);
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
