###############################################################################
# Nessus Vulnerability Test
#
###############################################################################
include("compat.inc");

if(description)
{
  script_id(51799100);
  script_version("$Revision: 10852 $");
  script_name(english:"Hikvision backup weak passwd vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_require_ports("Services/www", 80);
  script_set_attribute(attribute:"solution", value:"change the passwds");
  script_set_attribute(
    attribute:"description",
    value:"Detect the Hikvision backup weak passwd vulnerability.");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("webapp_func.inc");


port=get_http_port(default:80);
#display("port=="+port+'\r\n');

host = get_host_name();

 url1="/index.php"; 
		req1 = string(
		  'GET ',url1,' HTTP/1.1\r\n',
		  'Host: ', host,':',port,'\r\n',
		  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n',
		  'Accept:text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n',
		  'Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n',
		  'Accept-Encoding: gzip,deflate\r\n',
		  'Connection: close\r\n',
		  'Upgrade-Insecure-Requests: 1\r\n',
		  'Cookie: username=admin; passcode=12345\r\n',
		  '\r\n'
		);
 res1 = http_keepalive_send_recv(port:port, data:req1); 
 
 
 if("200 OK"><res1 && "Cache-Control"><res1 && "add_plan_dlg"><res1){
	if (report_verbosity > 0)
	{
	  header = 'please change your password, weak password with the following URL';
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
