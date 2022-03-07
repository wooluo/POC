###############################################################################
# Nessus Vulnerability Test
#
###############################################################################

if(description)
{
  script_id(51799154);
  script_version("$Revision: 10852 $");
  script_name(english:"AXIS Information disclosure vulnerability");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_set_attribute(attribute:"risk_factor", value:"Medium");
  script_require_ports("Services/www", 80);
  script_set_attribute(attribute:"solution", value:"update the version");
  script_set_attribute(
    attribute:"description",
    value:"Detect AXIS Information disclosure vulnerability.");
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



post_url = '/index.html/test.srv';
host = get_host_name();
postdata ="action=get_htmlform&return_page=vultest";
res = http_send_recv3(
  port: port,
  method: "POST",
  item: post_url,
  data: postdata,
add_headers: make_array("Host",host,"User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Accept", "text/html, application/xhtml+xml,*/*","Content-Type","application/x-www-form-urlencoded","Accept-Encoding","gzip,deflate","Origin",host,"Referer",host));	 
 

		if("303"><res[0]&&"vultest"><res[1]&&"vultest"><res[2]){
			if (report_verbosity > 0)
			{
			  header = 'Information disclosure with the following URL';
			  report = get_vuln_report(
				items  : post_url,
				port   : port,
				header : header
			  );
			  security_hole(port:port, extra:report);
			}
if (report_verbosity > 0) security_hole(port:port, extra:http_last_sent_request()+res[1]+res[2]);
			  else security_hole(port);
		}

exit(0);
