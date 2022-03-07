############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if (description)
{
  script_id(51799284);
  script_version("1.3");
  script_name(english:"Unauthorized access vulnerability in phpmyadmin of pagoda panel");
  script_summary(english:"Unauthorized access vulnerability in phpmyadmin of pagoda panel");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"description", value:"Unauthorized access vulnerability in phpmyadmin of pagoda panel");
  script_set_attribute(attribute:"solution", value:"update system");
  script_set_attribute(attribute:"vuln_publication_date",value:"2018/10/11");
  script_set_attribute(attribute:"patch_publication_date",value:"2018/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/22");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_require_ports("Services/www", 80, 443);
  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");


function check_vuln(port){
	url = "/pma/";
	req = http_send_recv3(method: "GET", port: 888,item: url, add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Content-Type","application/x-www-form-urlencoded"));
	if("200 O">< req[0] && "information_schema</a>" >< req[2] && "./url.php?url=" >< req[2] && "phpmyadmin" >< req[2]){
	    security_hole(port:888, extra:req[2]);
	}

}

function check_vuln_ssl(port){
	res = http_get(item:"/pma/",port:888);
	ssl_req = https_req_get(port:888 , request:res);
	if("200 O"><ssl_req && "information_schema</a>" >< ssl_req && "./url.php?url=" >< ssl_req && "phpmyadmin" >< ssl_req){
		security_hole(port:888, extra:ssl_req);
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
