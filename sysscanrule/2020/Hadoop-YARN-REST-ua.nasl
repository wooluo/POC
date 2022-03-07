############################################################
# Author: shiyunshu
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799233);
 name = "Hadoop YARN ResourceManager system REST API - Unauthorized access";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");  
 script_set_attribute(attribute:"description", value:"Hadoop is a distributed system framework launched by the Apache foundation. It uses the famous MapReduce algorithm for distributed processing. Yarn is the resource management system of Hadoop cluster.The improper configuration of Hadoop YARN resource management system can result in unauthorized access, which can be used maliciously by attackers. Attackers can execute arbitrary instructions through REST API deployment tasks without authentication, and finally take full control of the server.");
 script_set_attribute(attribute:"solution", value:"1.Network access control: use 'ECS/VPC security group' or 'host firewall' to control the access source IP of 'affected service port'. 2.If your own Hadoop environment only provides services for the intranet, please do not publish the Hadoop service port to the Internet. 3.If you use self built Hadoop, update the patch in time according to the actual situation. Hadoop provides security authentication function in version 2.X or above, and adds Kerberos authentication mechanism. It is recommended to enable Kerberos authentication function.");
 script_end_attributes();
 script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
 script_require_ports("Services/www", 8088);
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
	url = string("/ws/v1/cluster/info");
	req = http_send_recv3(method: "GET", port: port, item: url);
	if( req[2] == NULL) exit(0);
	if( "200 O">< req[0] && "resourceManagerVersionBuiltOn" >< req[2] && "hadoopVersion" >< req[2]){
	  	if (report_verbosity > 0) security_hole(port:port, extra:req[2]);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	url = string("/ws/v1/cluster/info");
	res = http_send_recv3(method: "GET", port: port, item: url);
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( "200 O"><ssl_req && "resourceManagerVersionBuiltOn" ><ssl_req && "hadoopVersion" ><ssl_req){
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