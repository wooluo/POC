###############################################################################
# Nessus Vulnerability Test
#
###############################################################################

if(description)
{
  script_id(51799095);
  script_version("$Revision: 10852 $");
  script_name(english:"Hikvision Weak password vulnerability");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"solution", value:"change your password");
  script_set_attribute(
    attribute:"description",
    value:"Detect Hikvision Weak password vulnerability.");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
#include("http_func.inc");
#include("http_keepalive.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("url_func.inc");
include("http.inc");



port=get_http_port(default:80);
#display("port=="+port);
host = get_host_name();

url = '/license!getExpireDateOfDays.action';


res1 = http_send_recv3(
  port: port,
  method: "GET",
  item: url
);


post_url = '/axis2-admin/login';

postdata ="userName=admin&password=axis2&submit=+Login+";
res = http_send_recv3(
  port: port,
  method: "POST",
  item: post_url,
  data: postdata,
add_headers: make_array("Host",host,"User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Accept", "text/html, application/xhtml+xml,*/*","Content-Type","application/x-www-form-urlencoded","Accept-Encoding","gzip,deflate","Origin",host,"Referer",host));	 
 

		if("200 OK"><res[0]&&"Operation Specific Chains"><res[2] && "iVMS-5000"><res1[2] && "200 OK"><res1[0]){
			if (report_verbosity > 0)
			{
			  header = 'Weak password with the following URL';
			  report = get_vuln_report(
				items  : post_url,
				port   : port,
				header : header
			  );
			  security_hole(port:port, extra:report);
			}
if (report_verbosity > 0) security_hole(port:port, extra:http_last_sent_request()+res[2]+res1[2]);
			  else security_hole(port);
		}

exit(0);
