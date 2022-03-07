###############################################################################
# Nessus Vulnerability Test
#
###############################################################################
include("compat.inc");

if(description)
{
  script_id(51799127);
  script_version("$Revision: 10852 $");
  script_name(english:"Dahua weak passwd vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_require_ports("Services/www", 80);
  script_set_attribute(attribute:"solution", value:"change the passwds");
  script_set_attribute(
    attribute:"description",
    value:"Detect the Dahua weak passwd vulnerability.");
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

host = get_host_name();

post_url = '/RPC2_Login';
header = make_array("Host",host+":"+port,"User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Accept-Encoding","gzip, deflate");

data='{"method":"global.login","params":{"userName":"admin","password":"","clientType":"Dahua3.0-Web3.0"},"id":10000}:';

res = http_send_recv3(
  port: port,
  method: "POST",
  item: post_url,
  data: data,
add_headers: header
);


#display("res=="+res+'\r\n');
#display("res[0]=="+res[0]+'\r\n');
#display("res[1]=="+res[1]+'\r\n');
#display("res[2]=="+res[2]+'\r\n');
sessionid = eregmatch(string: res[2], pattern: 'session" : ([0-9]*)',icase:TRUE);
#display("sessionid=="+sessionid[1]+'\r\n');

postdata ='{"method":"global.login","session":'+sessionid[1]+',"params":{"userName":"admin","password":"6QNMIQGe","clientType":"Dahua3.0-Web3.0", "authorityType":"OldDigest"},"id":10000}:';
postdata1 ='{"method":"global.login","session":'+sessionid[1]+',"params":{"userName":"888888","password":"4WzwxXxM","clientType":"Dahua3.0-Web3.0", "authorityType":"OldDigest"},"id":10000}:';
postdata2 ='{"method":"global.login","session":'+sessionid[1]+',"params":{"userName":"666666","password":"sh15yfFM","clientType":"Dahua3.0-Web3.0", "authorityType":"OldDigest"},"id":10000}:';
postdata3 ='{"method":"global.login","session":'+sessionid[1]+',"params":{"userName":"default","password":"OxhlwSG8","clientType":"Dahua3.0-Web3.0", "authorityType":"OldDigest"},"id":10000}:';
datas = make_list(postdata,postdata1,postdata2,postdata3);
header1 = make_array("Host",host+":"+port,"User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Accept-Encoding","gzip,deflate","Cookie","DhWebClientSessionID="+sessionid[1]);
#display("header=="+header1+'\r\n');
foreach data1 (datas){
	res1 = http_send_recv3(
	  port: port,
	  method: "POST",
	  item: post_url,
	  data: data1,
	add_headers: header1
	);
#display("data"+data1);	
#display("res1[0]=="+res1[0]+'\r\n');
#display("res1[1]=="+res1[1]+'\r\n');
#display("res1[2]=="+res1[2]+'\r\n');
		if("200 OK"><res1[0] && sessionid[1]><res1[2] && '"result" : true'><res1[2]){
	if (report_verbosity > 0) security_hole(port:port, extra:http_last_sent_request()+res1[2]);
			  else security_hole(port);
		}
}	





exit(0);
