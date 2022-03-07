###############################################################################
# Nessus Vulnerability Test
#
###############################################################################
include("compat.inc");

if(description)
{
  script_id(51799066);
  script_version("$Revision: 10852 $");
  script_name(english:"Pelco Sarix Pro weak passwd vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"see_also", value:"http://www.cnvd.org.cn/flaw/show/CNVD-2017-36508");
  script_set_attribute(attribute:"solution", value:"change the passwds");
  script_set_attribute(
    attribute:"description",
    value:"Detect the Pelco Sarix Pro weak passwd vulnerability.");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port=get_http_port(default:80);
#display("port=="+port+'\r\n');


post_url = '/auth/validate';

user = "admin";
pass = "admin";
host = get_host_name();
postdata =
  "username=" + user + "&" +
  "password=" + pass;
res = http_send_recv3(
  port: port,
  method: "POST",
  item: post_url,
  data: postdata,
add_headers: make_array("Host",host+":"+port,"User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Content-Type", "application/x-www-form-urlencoded","Accept-Encoding","gzip, deflate","Origin",host+":"+port,"Referer",host+":"+port,"Cookie", "PHPSESSID=kqkgug0va9frvgthm1c9f49be2; svcts=1574674466")
);
		if("authos-token"><res[1]){
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
if (report_verbosity > 0) security_hole(port:port, extra:http_last_sent_request()+res[1]);
			  else security_hole(port);
		}


exit(0);
