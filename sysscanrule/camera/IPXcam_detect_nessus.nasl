###############################################################################
# Nessus Vulnerability Test
#
###############################################################################

if(description)
{
  script_id(51799087);
  script_version("$Revision: 10852 $");
  script_name(english:"IPX weak passwd vulnerability");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_require_ports("Services/www", 80);
  script_set_attribute(attribute:"solution", value:"change the password");
  script_set_attribute(
    attribute:"description",
    value:"Detect the weak passwd vulnerability.");
  exit(0);
}
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("openvas-https2.inc");

function http_vul(port){
        url="/ix/index.htm";
		req = string(
		  'GET ',url,' HTTP/1.1\r\n',
		  'Host: ', host,':',port,'\r\n',
		  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n',
		  'Accept:text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n',
		  'Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n',
		  'Accept-Encoding: gzip,deflate\r\n',
		  'Connection: close\r\n',
		  'Upgrade-Insecure-Requests: 1\r\n',
		  'Authorization: Basic cm9vdDpBZG1pbg==\r\n',
		  '\r\n'
		);
		res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
#display("port=="+port+"req=="+req+'\r\n');
 #               display("res=="+res+'\r\n');
		if("200 OK"><res &&"var g_AlarmCheckTime = 555"><res){
			if (report_verbosity > 0)
			{
			  header = 'Weak password with the following URL';
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
}

function https_vul(port){
        url="/ix/index.htm";
		req = string(
		  'GET ',url,' HTTP/1.1\r\n',
		  'Host: ', host,':',port,'\r\n',
		  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n',
		  'Accept:text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n',
		  'Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n',
		  'Accept-Encoding: gzip,deflate\r\n',
		  'Connection: close\r\n',
		  'Upgrade-Insecure-Requests: 1\r\n',
		  'Authorization: Basic cm9vdDpBZG1pbg==\r\n',
		  '\r\n'
		);
		ssl_req = https_req_get(port:port , request:req);
#display("port=="+port+"req=="+req+'\r\n');
 #               display("ssl_req=="+ssl_req+'\r\n');
		if("200 OK"><ssl_req &&"var g_AlarmCheckTime = 555"><ssl_req){
			if (report_verbosity > 0){
if (report_verbosity > 0) security_hole(port:port, extra:req+ssl_req);
			  else security_hole(port);
			}
		}
}
host = get_host_name();
kbs = get_kb_list("www/banner/*");
foreach k (keys(kbs)) {
	port = substr(k,11);
	ssl = get_kb_list("SSL/Transport/"+port);
	if(!ssl) {
   		http_vul(port:port);
	} else {
   		https_vul(port:port);
	}
}

exit(0);
