###############################################################################
# Nessus Vulnerability Test
#
###############################################################################

if(description)
{
  script_id(51799117);
  script_version("$Revision: 10852 $");
  script_name(english:"foscam weak passwd vulnerability");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_set_attribute(attribute:"risk_factor", value:"Medium");
  script_require_ports("Services/www", 60001);
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

port=get_http_port(default:60001);
#display("port=="+port);

 url1="/snapshot.cgi?user=admin&pwd=&count=1"; 
 req1 = http_get(item:url1, port:port);  
 res1 = http_keepalive_send_recv(port:port, data:req1); 
	 
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


exit(0);
