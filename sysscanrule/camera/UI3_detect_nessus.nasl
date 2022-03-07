###############################################################################
# Nessus Vulnerability Test
#
###############################################################################

if(description)
{
  script_id(51799049);
  script_version("$Revision: 10852 $");
  script_name(english:"UI3 Unauthorized access vulnerability");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_set_attribute(attribute:"risk_factor", value:"Medium");
  script_require_ports("Services/www", 81);
  script_set_attribute(attribute:"solution", value:"update to the new version");
  script_set_attribute(
    attribute:"description",
    value:"Detect UI3 Unauthorized access vulnerability.");
  exit(0);
}
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("openvas-https2.inc");

host=get_host_name();
port=get_http_port(default:81);
#display("port=="+port);
 url="/ui3.htm"; 
 req = http_get(item:url, port:port);  
 res = http_keepalive_send_recv(port:port, data:req); 

 if("200 OK"><res && "Live View"><res && "Current Group"><res){
	if (report_verbosity > 0)
	{
	  header = 'Unauthorized access with the following URL';
	  report = get_vuln_report(
		items  : url,
		port   : port,
		header : header
	  );
	  security_hole(port:port, extra:report);
	}
if (report_verbosity > 0) security_hole(port:port, extra:req+res);
			  else security_hole(port);
 }	 

if (get_kb_list("SSL/Transport/"+port)){
        url="/ui3.htm";
		req = string(
		  'GET ',url,' HTTP/1.1\r\n',
		  'Host: ', host,'\r\n',
		  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n',
		  'Accept:text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n',
		  'Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n',
		  'Accept-Encoding: gzip,deflate\r\n',
		  'Connection: close\r\n',
		  'Upgrade-Insecure-Requests: 1\r\n',
		  '\r\n'
		);
		ssl_req = https_req_get(port:port , request:req);
#display('\r\n'+req+'\r\n');
#display('\r\nsslreq==>'+ssl_req+'\r\n');
 if("200 OK"><ssl_req && "Live View"><ssl_req && "Current Group"><ssl_req){
	if (report_verbosity > 0)
	{
	  header = 'Unauthorized access with the following URL';
	  report = get_vuln_report(
		items  : url,
		port   : ssl_ports,
		header : header
	  );
	  security_hole(port:ssl_ports, extra:req);
	}
if (report_verbosity > 0) security_hole(port:ssl_ports, extra:req+ssl_req);
			  else security_hole(ssl_ports);
 }
} 
exit(0);
