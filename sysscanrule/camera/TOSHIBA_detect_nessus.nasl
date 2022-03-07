###############################################################################
# Nessus Vulnerability Test
#
###############################################################################

if(description)
{
  script_id(51799054);
  script_version("$Revision: 10852 $");
  script_name(english:"TOSHIBA Unauthorized access vulnerability");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_set_attribute(attribute:"risk_factor", value:"Medium");
  script_require_ports("Services/www", 80);
  script_set_attribute(attribute:"solution", value:"update to the new version");
  script_set_attribute(
    attribute:"description",
    value:"Detect TOSHIBA Unauthorized access vulnerability.");
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
 url="/user_view_header_S.htm"; 
 req = http_get(item:url, port:port);  
 res = http_keepalive_send_recv(port:port, data:req); 
 url1="/user_oneshot.htm"; 
 req1 = http_get(item:url1, port:port);  
 res1= http_keepalive_send_recv(port:port, data:req1); 
#display(res1);
 
 if(("200 OK"><res && ("TOSHIBA Network Camera User Viewer Header for Single-Screen"><res))||("200 OK"><res1 && ("TOSHIBA User 1 Shot"><res1))){
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
if (report_verbosity > 0) security_hole(port:port, extra:req+res+req1+res1);
			  else security_hole(port);
 }	 
 

exit(0);
