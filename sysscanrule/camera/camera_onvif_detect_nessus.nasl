###############################################################################
# Nessus Vulnerability Test
#
###############################################################################
include("compat.inc");

if(description)
{
  script_id(51799141);
  script_version("$Revision: 10852 $");
  script_name(english:"Camera Onvif Information disclosure vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_set_attribute(attribute:"risk_factor", value:"Medium");
  script_require_ports("Services/www", 80);
  script_set_attribute(attribute:"solution", value:"update your version");
  script_set_attribute(
    attribute:"description",
    value:"Detect the Camera Onvif Information disclosure vulnerability.");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");
include("openvas-https2.inc");


function check_vuln(port){
	post_url = '/onvif/device_service';

	host = get_host_name();
	postdata ='<?xml version="1.0" encoding="UTF-8"?>\r\n
	<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><SOAP-ENV:Body><tds:GetCapabilities></tds:GetCapabilities></SOAP-ENV:Body></SOAP-ENV:Envelope>';

	postdata1 ='<?xml version="1.0" encoding="UTF-8"?>\r\n
	<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><SOAP-ENV:Body><tds:GetDeviceInformation ></tds:GetDeviceInformation ></SOAP-ENV:Body></SOAP-ENV:Envelope>';

	postdatas = make_list(postdata,postdata1);
	foreach data (postdatas){
		res = http_send_recv3(
		  port: port,
		  method: "POST",
		  item: post_url,
		  data: data,
		add_headers: make_array("Host",host+":"+port,"User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Content-Type", "application/x-www-form-urlencoded","Accept-Encoding","gzip, deflate","Origin",host+":"+port,"Referer",host+":"+port)
		);
		#display(res[0]);
		#display(res[2]);
		if("200 OK"><res[0]&&"tt:XAddr"><res[2]&&"tt:AnalyticsModuleSupport"><res[2]){
			if (report_verbosity > 0)
			{
			  header = 'Information disclosure 1 with the following URL';
			  report = get_vuln_report(
				items  : post_url,
				port   : port,
				header : header
			  );
			  security_hole(port:port, extra:report);
			}
if (report_verbosity > 0) security_hole(port:port, extra:http_last_sent_request()+res[2]);
			  else security_hole(port);
		}
		if("200 OK"><res[0]&&"SerialNumber"><res[2]&&"FirmwareVersion"><res[2]){
			if (report_verbosity > 0)
			{
			  header = 'Information disclosure 2 with the following URL';
			  report = get_vuln_report(
				items  : post_url,
				port   : port,
				header : header
			  );
			  security_hole(port:port, extra:report);
			}
if (report_verbosity > 0) security_hole(port:port, extra:http_last_sent_request()+res[2]);
			  else security_hole(port);
		}
	}
}

function check_vuln_ssl(port){
	post_url = '/onvif/device_service';

	host = get_host_name();
	postdata ='<?xml version="1.0" encoding="UTF-8"?>\r\n
	<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><SOAP-ENV:Body><tds:GetCapabilities></tds:GetCapabilities></SOAP-ENV:Body></SOAP-ENV:Envelope>';


	postdata1 ='<?xml version="1.0" encoding="UTF-8"?>\r\n
	<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><SOAP-ENV:Body><tds:GetDeviceInformation ></tds:GetDeviceInformation ></SOAP-ENV:Body></SOAP-ENV:Envelope>';

	postdatas = make_list(postdata,postdata1);
	foreach data (postdatas){	
		req = string(
		  'POST ',post_url,' HTTP/1.1\r\n',
		  'Host: ', host,':',port,'\r\n',
		  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n',
		  'Accept:text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n',
		  'Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n',
		  'Accept-Encoding: gzip,deflate\r\n',
		  'Connection: close\r\n',
		  'Upgrade-Insecure-Requests: 1\r\n',
		  '\r\n',
		  data
		);
		ssl_req = https_req_get(port:port , request:req);
		#display(res[0]);
		#display(res[2]);


		if("200 OK"><ssl_req[0]&&"tt:XAddr"><ssl_req[2]&&"tt:AnalyticsModuleSupport"><ssl_req[2]){
			if (report_verbosity > 0)
			{
			  header = 'Information disclosure 1 with the following URL';
			  report = get_vuln_report(
				items  : post_url,
				port   : port,
				header : header
			  );
			  security_hole(port:port, extra:req);
			}
if (report_verbosity > 0) security_hole(port:port, extra:req+ssl_req[2]);
			  else security_hole(port);
		}
	}
}

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

exit(0);
