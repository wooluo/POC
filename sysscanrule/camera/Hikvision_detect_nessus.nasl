if(description)
{
  script_id(51799099);
  script_version("$Revision: 10852 $");
  script_name(english:"Hikvision Multiple vulnerabilities vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_dependencies( "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_set_attribute(attribute:"solution", value:"update to the new version");
  script_set_attribute(
    attribute:"description",
    value:"Detect Hikvision Multiple vulnerabilities.");
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
 url="/upnpdevicedesc.xml";
 req = http_get(item:url, port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 url1="/Security/users?auth=YWRtaW46MTEK";
 req1 = http_get(item:url1, port:port);
 res1 = http_keepalive_send_recv(port:port, data:req1);
 url2="/onvif-http/snapshot?auth=YWRtaW46MTEK";
 req2 = http_get(item:url2, port:port);
 res2 = http_keepalive_send_recv(port:port, data:req2);
 url3="/System/configurationFile?auth=YWRtaW46MTEK";
 req3 = http_get(item:url3, port:port);
 res3 = http_keepalive_send_recv(port:port, data:req3);

 if("200 OK"><res && "schemas-upnp-org:device-1-0"><res){
	if (report_verbosity > 0)
	{
	  header = 'Information disclosure 1 with the following URL';
	  report = get_vuln_report(
		items  : url,
		port   : port,
		header : header
	  );
	  security_hole(port:port, extra:report);
	}
	# if (report_verbosity > 0) security_hole(port:port, extra:url+req+res);
	else security_hole(port);
 }
 if("200 OK"><res1 && "userName"><res1 && "macAddress"><res1){
	if (report_verbosity > 0)
	{
	  header = 'Information disclosure 2 with the following URL';
	  report = get_vuln_report(
		items  : url1,
		port   : port,
		header : header
	  );
	  security_hole(port:port, extra:report);
	}
	# if (report_verbosity > 0) security_hole(port:port, extra:req1+res1);
	else security_hole(port);
 }
 if("200 OK"><res2 && "image/jpeg"><res2 && "JFIF"><res2){
	if (report_verbosity > 0)
	{
	  header = 'Unauthorized access with the following URL';
	  report = get_vuln_report(
		items  : url2,
		port   : port,
		header : header
	  );
	  security_hole(port:port, extra:report);
	}
	# if (report_verbosity > 0) security_hole(port:port, extra:req2+res2);
	else security_hole(port);
 }
 if("200 OK"><res3 && "application/binary"><res3){
	if (report_verbosity > 0)
	{
	  header = 'Information disclosure 3 with the following URL';
	  report = get_vuln_report(
		items  : url3,
		port   : port,
		header : header
	  );
	  security_hole(port:port, extra:report);
	}
	# if (report_verbosity > 0) security_hole(port:port, extra:req3+res3);
	else security_hole(port);
 }
exit(0);
