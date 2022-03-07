###############################################################################
# Nessus Vulnerability Test
#
###############################################################################

if(description)
{
  script_id(51799153);
  script_version("$Revision: 10852 $");
  script_name(english:"AXIS unauthenticated vulnerability");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_set_attribute(attribute:"risk_factor", value:"Medium");
  script_dependencies( "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_set_attribute(attribute:"solution", value:"Take the device offline from the public network");
  script_set_attribute(
    attribute:"description",
    value:"Detect AXIS unauthenticated vulnerability.");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("webapp_func.inc");




port=get_http_port(default:80);
#display("port=="+port);

 url1="/view/index.shtml"; 
 req1 = http_get(item:url1, port:port);  
 res1 = http_keepalive_send_recv(port:port, data:req1); 

 
 
 if(("200 OK"><res1 && ("/pics/UpperLeft.gif"><res1))){
	if (report_verbosity > 0)
	{
	  header = 'Take the device offline from the public network，AXIS unauthenticated with the following URL';
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
