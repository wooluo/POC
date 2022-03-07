############################################################
# Author: shiyunshu
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799234);
 name = "Hadoop - unauthorized access";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");  
 script_set_attribute(attribute:"description", value:"Hadoop is a distributed system infrastructure developed by the Apache foundation.Users can develop distributed programs without knowing the details of the distributed bottom layer. Make full use of the power of cluster for high-speed operation and storage.By default, Hadoop allows any user to access the management interface.");
 script_set_attribute(attribute:"solution", value:"1. It is recommended to prohibit public network access to these ports according to the principle of security minimization. If you have to open to the public due to business needs, please use the security group policy provided by ECS to specify the access source IP access port business. If not necessary, close the Hadoop Web management page; 2. Turn on service level authentication, such as Kerberos authentication; 3. Deploy reverse proxy systems such as Knox and Nginx to prevent unauthorized users from accessing; 4. Use the switch or firewall policy to configure the access control policy (ACL), and forbid or restrict the trusted IP address of multiple ports opened by Hadoop by default to the public network to access related ports including 50070 and WebUI.");
 script_end_attributes();
 script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
 script_require_ports("Services/www", 50070);
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


function check_vuln(port){
	if ( !get_port_state(port) ) exit(0);
	url = string("/dfshealth.html#tab-overview");
	req = http_send_recv3(method: "GET", port: port, item: url);
	if( req[2] == NULL) exit(0);
	con = url + req[1] + req[2];
	if( "200 O">< req[0] && '<div class="navbar-brand">Hadoop</div>' >< req[2] && '<a href="#tab-startup-progress">Startup Progress</a>' >< req[2] && '<div class="page-header"><h1>NameNode Storage</h1>' >< req[2]){
	  	if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	url = string("/dfshealth.html#tab-overview");
	res = http_send_recv3(method: "GET", port: port, item: url);
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = url + ssl_req;
	if( "200 O"><ssl_req && '<div class="navbar-brand">Hadoop</div>'><ssl_req && '<a href="#tab-startup-progress">Startup Progress</a>'><ssl_req && '<div class="page-header"><h1>NameNode Storage</h1>'><ssl_req){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
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