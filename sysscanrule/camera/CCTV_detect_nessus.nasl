###############################################################################
# Nessus Vulnerability Test
#
###############################################################################

if(description)
{
  script_id(51799136);
  script_version("$Revision: 10852 $");
  script_name(english:"Multiple CCTV vulnerability");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_require_ports("Services/www", 60001);
  script_set_attribute(attribute:"risk_factor", value:"Medium");
  script_set_attribute(attribute:"see_also", value:"https://www.pentestpartners.com/security-blog/pwning-cctv-cameras/");
  script_set_attribute(attribute:"solution", value:"Upgrade to new version.");
  script_set_attribute(
    attribute:"description",
    value:"Detect the vulnerabilities of the CCTV.");
  exit(0);
}
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("webapp_func.inc");

port=get_http_port(default:60001);
#display("port=="+port);

host = get_host_name();

req = string(
  'GET /view2.html HTTP/1.1\r\n',
  'Host: ', host, '\r\n',
  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n',
  'Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*.*;q=0.5\r\n',
  'Accept-Language: en-us,en;q=0.5\r\n',
  'Accept-Encoding: gzip,deflate\r\n',
  'Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n',
  'Referer: http://', host, '/\r\n',
  'Cookie: dvr_camcnt=8; dvr_clientport=80; dvr_sensorcnt=4; lxc_save=admin,123 ; dvr_usr=admin; dvr_pwd=admin\r\n',
  '\r\n'
);



res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);	 


 url1="/cgi-bin/snapshot.cgi?chn=0&f=1&u=admin&p="; 
 req1 = http_get(item:url1, port:port);  
 res1 = http_keepalive_send_recv(port:port, data:req1); 
 
 url2="/shell?ps"; 
 req2 = http_get(item:url2, port:port);  
 res2 = http_keepalive_send_recv(port:port, data:req2); 
 
 if("200 OK"><res && ("Connect all"><res ||"Disconnect all"><res)){
	if (report_verbosity > 0)
	{
	  header = 'Identity bypass with the following URL';
	  report = get_vuln_report(
		items  : "/view2.html",
		port   : port,
		header : header
	  );
	  security_hole(port:port, extra:report);
	}
if (report_verbosity > 0) security_hole(port:port, extra:req+res);
			  else security_hole(port);
 }
 if(("200 OK"><res1 && ("Content-Type: image/jpeg"><res1))){
	if (report_verbosity > 0)
	{
	  header = 'please change your password，default password with the following URL';
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
 if("200 OK"><res2 && "PID "><res2 &&"COMMAND"><res2){
	if (report_verbosity > 0)
	{
	  header = 'please update your version,backdoor found with the following URL';
	  report = get_vuln_report(
		items  : url2,
		port   : port,
		header : header
	  );
	  security_hole(port:port, extra:report);
	}
if (report_verbosity > 0) security_hole(port:port, extra:req2+res2);
			  else security_hole(port);
 }

exit(0);
