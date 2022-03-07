###############################################################################
# Nessus Vulnerability Test
#
###############################################################################

if(description)
{
  script_id(51799035);
  script_version("$Revision: 10852 $");
  script_name(english:"Watchdog weak password vulnerability");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_require_ports("Services/www", 7001);
  script_set_attribute(attribute:"solution", value:"change your password");
  script_set_attribute(
    attribute:"description",
    value:"Detect Watchdog weak password vulnerability.");
  exit(0);
}
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("webapp_func.inc");

host=get_host_name();
port=get_http_port(default:7001);
#display("port=="+port);



 url1="/api/getCurrentUser"; 
		req1 = string(
		  'GET ',url1,' HTTP/1.1\r\n',
		  'Host: ', host,':',port,'\r\n',
		  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n',
		  'Accept: application/json, text/plain, */*\r\n',
		  'Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n',
		  'Accept-Encoding: gzip,deflate\r\n',
		  'Cookie: X-runtime-guid={058b0b94-9451-4bd0-bf3c-961d3b5fdcf5}; Authorization=Digest; auth_rtsp=YWRtaW46NTk4YWVkZGZhYjlhODpjNGUwYThhOGI0ZWQzYWVmMDhhMjc5NTJhNTQ0NDkzNQ%3D%3D; nonce=598aeddfab9a8; realm=digitalwatchdog; auth=YWRtaW46NTk4YWVkZGZhYjlhODoyNjY1MWNjZWNmMmUzYmNjOTJjNGJhNzFmMGNhOWYyZA%3D%3D\r\n',
		  '\r\n'
		);
 res1 = http_keepalive_send_recv(port:port, data:req1); 
#display("req=="+req1+'\r\n');
#display("res=="+res1+'\r\n'); 
 
 if("200 OK"><res1 && "isEnabled"><res1){
	if (report_verbosity > 0)
	{
	  header = 'please change your password，Watchdog weak password with the following URL';
	  report = get_vuln_report(
		items  : url1,
		port   : port,
		header : header
	  );
	  security_hole(port:port, extra:report);
	}
if (report_verbosity > 0) security_hole(port:port, extra:req1+res1);
			  else security_hole(port);
 }


exit(0);
