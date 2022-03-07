############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799135);
 name = "ContaCam camera - unauthorized access";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"description", value:"The ContaCam camera is not authorized to access. The camera does not have any authentication method. Anyone can view the monitoring content.");
 script_set_attribute(attribute:"solution", value:"White list restricts access to IP.");
 script_end_attributes();
 script_require_ports("Services/www", 80);
 exit(0);
}


#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("misc_func.inc");
include("openvas-https.inc");


function check_vuln(port){
	if ( !get_port_state(port) ) exit(0);
	url1 = string("/");
	req1 = http_get(item:url1, port:port);
	buf1 = http_keepalive_send_recv(port:port,data:req1,bodyonly:FALSE);
	mat = eregmatch(string: buf1, pattern: 'iframe0" src="/([0-9a-zA-Z ._-]+)/snapsh');
	coo = mat[1];
	
	url = string("/",coo,"/poll.php");
	req = http_get(item:url, port:port);
	buf = http_keepalive_send_recv(port:port,data:req,bodyonly:FALSE);
	if( buf == NULL) exit(0);
	con = req + buf;
	if( "200 O"><buf && "Content-Type: image/jpeg"><buf && "56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz"><buf){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	
	url1 = string("/");
	req1 = http_get(item:url1, port:port);
	buf1 = http_keepalive_send_recv(port:port,data:req1,bodyonly:FALSE);
	mat = eregmatch(string: buf1, pattern: 'iframe0" src="/([0-9a-zA-Z ._-]+)/snapsh');
	coo = mat[1];

	url = string("/",coo,"/poll.php");
    req = http_get(item:url, port:port);
	ssl_req = https_req_get(port:port,request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( "200 O"><ssl_req && "Content-Type: image/jpeg"><ssl_req && "56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz"><ssl_req){
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