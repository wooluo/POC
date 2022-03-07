###############################################################################
# Nessus Vulnerability Test
#
###############################################################################

if(description)
{
  script_id(51799037);
  script_version("$Revision: 10852 $");
  script_name(english:"Vivotek Unauthenticated vulnerability");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_set_attribute(attribute:"risk_factor", value:"Medium");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_set_attribute(attribute:"solution", value:"change your password");
  script_set_attribute(
    attribute:"description",
    value:"Detect Vivotek Unauthenticated vulnerability.");
  exit(0);
}
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("webapp_func.inc");

host=get_host_name();
port=get_http_port(default:8080);

res = http_send_recv3(method: "GET", port: port, item: "/", add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Content-Type","application/x-www-form-urlencoded"));
if(">video_stream<" >< res[2]){

	url="/cgi-bin/viewer/video.jpg";
	res = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Content-Type","application/x-www-form-urlencoded"));
	
	if("200 OK"><res[0] && "image/jpeg"><res[1] ){
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
 
}
exit(0);
