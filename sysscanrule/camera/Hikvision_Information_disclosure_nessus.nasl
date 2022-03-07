###############################################################################
# Nessus Vulnerability Test
#
###############################################################################

if(description)
{
  script_id(51799096);
  script_version("$Revision: 10852 $");
  script_name(english:"Hikvision Information disclosure vulnerability");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_require_ports("Services/www", 80);
  script_set_attribute(attribute:"solution", value:"update the new version");
  script_set_attribute(
    attribute:"description",
    value:"Detect Hikvision Information disclosure vulnerability.");
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
 url='/userinfo/userInfo.php?userId=1'; 
 req = http_get(item:url, port:port);  
 res = http_keepalive_send_recv(port:port, data:req); 
 
 if("200 OK"><res && "url:'../data/fetchControlUnitTree.php?pId=0'"><res){
	if (report_verbosity > 0)
	{
	  header = 'Information disclosure with the following URL';
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
