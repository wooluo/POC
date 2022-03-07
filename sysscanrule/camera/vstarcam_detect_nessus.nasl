###############################################################################
# Nessus Vulnerability Test
#
###############################################################################

if(description)
{
  script_id(51799036);
  script_version("$Revision: 10852 $");
  script_name(english:"vstarcam weak passwd vulnerability");
  script_category(ACT_GATHER_INFO);
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_set_attribute(attribute:"see_also", value:"https://nosec.org/home/detail/1722.html");
  script_set_attribute(attribute:"solution", value:"change the passwds");
  script_set_attribute(
    attribute:"description",
    value:"Detect the vstarcam weak passwd vulnerability.");
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
url = "/index.htm";


req = string(
  'GET ',url,' HTTP/1.1\r\n',
  'Host: ', host,':',port,'\r\n',
  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n',
  'Accept:text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n',
  'Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n',
  'Accept-Encoding: gzip,deflate\r\n',
  'Connection: close\r\n',
  'Upgrade-Insecure-Requests: 1\r\n',
  'Authorization: Digest username=admin,realm=Vstarcam,nonce=d0c9a3f9305d25193a90728f518b84ab,uri=/index.htm,cnonce=9d8c245ec0ac5560b415da9ac8938d19,nc=00000001,algorithm=MD5,response=a4e3c098ca43e52ac7101b8f43b21150,qop=auth,opaque=5ccc069c403ebaf9f0171e9517f40e4\r\n',
  '\r\n'
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
#display(req);
#display(url+"   "+passwd+"   res=="+res+'\r\n');
if("200 OK"><res && "pda.htm"><res){
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

exit(0);
