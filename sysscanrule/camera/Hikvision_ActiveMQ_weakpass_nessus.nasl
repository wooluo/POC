###############################################################################
# Nessus Vulnerability Test
#
###############################################################################

if(description)
{
  script_id(51799101);
  script_version("$Revision: 10852 $");
  script_name(english:"Hikvision ActiveMQ Weak password vulnerability");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_require_ports("Services/www", 80);
  script_set_attribute(attribute:"solution", value:"change your password");
  script_set_attribute(
    attribute:"description",
    value:"Detect Hikvision ActiveMQ Weak password vulnerability.");
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



port=get_http_port(default:7288);
#display("port=="+port);
host = get_host_name();

url = '/';


res = http_send_recv3(
  port: port,
  method: "GET",
  item: url
);
if("200 OK">!<res[0]||"data/login.php">!<res[2]){

	exit(0);
}

if (!get_port_state(8161)) exit(0);


 url1="/admin/topics.jsp"; 
res1 = http_send_recv3(
  port:8161,
  method: "GET",
  item: url1,
add_headers: make_array("Host",host,"User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Accept", "text/html, application/xhtml+xml,*/*","Content-Type","application/x-www-form-urlencoded","Accept-Encoding","gzip,deflate","Authorization","Basic dXNlcjp1c2Vy"));

		if("200 OK"><res1[0]&&"Subscribers"><res1[2] && "Scheduled"><res1[2] && "Number Of Consumers"><res1[2]){
			if (report_verbosity > 0)
			{
			  header = 'Weak password with the following URL';
			  report = get_vuln_report(
				items  : url1,
				port   : 8161,
				header : header
			  );
			  security_hole(port:8161, extra:report);
			}
if (report_verbosity > 0) security_hole(port:8161, extra:http_last_sent_request()+res1[2]);
			  else security_hole(8161);
		}

exit(0);
