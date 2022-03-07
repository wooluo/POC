############################################################
# Author: shiyunshu
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799235);
 name = "Couchdb remote api No auth";
 script_name(name);
 script_category(ACT_GATHER_INFO);
 script_family("Databases");
 script_dependencies("find_service.nasl");
 script_set_attribute(attribute:"risk_factor", value:"High");  
 script_set_attribute(attribute:"description", value:"CouchDB is an open-source document oriented database management system, which can be accessed through the RESTful JavaScript Object Notation (JSON) API. By default, the restful API interface will be opened on port 5984. If SSL is used, it will listen on port 6984 for database management functions. Its HTTP Server is not verified when it is turned on by default, and is bound to 0.0.0.0. All users can access through API, resulting in unauthorized access.");
 script_set_attribute(attribute:"solution", value:"1. Specify the IP address of CouchDB binding \(you need to restart CouchDB to take effect\). Find 'bind_address = 0.0.0.0' in the  /etc/couchdb/local.ini file, change 0.0.0.0 to 127.0.0.1, and save. Note: only the local machine can access CouchDB after modification. 2. Set the access password \(you need to restart CouchDB to take effect\). Find the '[admins]' field configuration password in /etc/couchdb/local.ini. 3. Set WWW-Authenticate to force authentication.");
 script_end_attributes();
 script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
 script_require_ports("Services/www", 5984);
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
	url = string("/_config/");
	req = http_send_recv3(method: "GET", port: port, item: url);
	if( req[2] == NULL) exit(0);
	if( "200 O">< req[0] && '"allow_persistent_cookies":' >< req[2] && "couch_httpd_" >< req[2] && '"replicator":'>< req[2]){
	  	if (report_verbosity > 0) security_hole(port:port, extra:req[2]);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	url = string("/_config/");
	res = http_send_recv3(method: "GET", port: port, item: url);
	req = http_last_sent_request();
    ssl_req = https_req_get(port:port , request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( "200 O"><ssl_req && '"allow_persistent_cookies":' ><ssl_req && "couch_httpd_"><ssl_req && '"replicator":'><ssl_req ){
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