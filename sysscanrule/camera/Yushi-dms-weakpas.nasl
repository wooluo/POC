############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799032);
 name = "Yushi technology data management server - weak password";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"description", value:"A large number of database leaks caused by weak password of Yushi technology data management server.");
 script_set_attribute(attribute:"solution", value:"Increase password strength.");
 script_end_attributes();
 script_require_ports("Services/www", 80);
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
	urls = make_list("/webui/login.php","/login.php");
	foreach url (urls){
		req = http_send_recv3(method: "GET", port: port, item: url);
		if( req[0] != 200 && req[2] == NULL) exit(0);
		mat = eregmatch(string: req[1], pattern: "Set-Cookie:.*PHPSESSID=([0-9a-zA-Z]+);");
		cookie = string("PHPSESSID=",mat[1]);
		req1 = http_send_recv3(
				port: port,
				method: "POST",
				item: url,
				data: "username=admin&passwd=e10adc3949ba59abbe56e057f20f883e&hideWeakPasswd=2",
				add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Accept", "text/html, application/xhtml+xml,*/*","Content-Type","application/x-www-form-urlencoded", "Content-Length", "71", "Cookie", cookie));
	
		if( req1[2] == NULL) exit(0);
		con = url + req1[0] + req1[1];
		if( "302">< req1[0] && "location: dmframe.php" >< req1[1]){
			if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
		}
	}
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	urls = make_list("/webui/login.php","/login.php");
	foreach url (urls){
		res = http_send_recv3(method: "GET", port: port, item: url);
		req = http_last_sent_request();
		ssl_req = https_req_get(port:port , request:req);
		if( "200 O" >!< ssl_req && ssl_req == NULL) exit(0);
		mat = eregmatch(string: ssl_req, pattern: "Set-Cookie:.*PHPSESSID=([0-9a-zA-Z]+);");
		cookie = string("PHPSESSID=",mat[1]);
		res1 = http_send_recv3(
				port: port,
				method: "POST",
				item: url,
				data: "username=admin&passwd=e10adc3949ba59abbe56e057f20f883e&hideWeakPasswd=2",
				add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0","Accept", "text/html, application/xhtml+xml,*/*","Content-Type","application/x-www-form-urlencoded", "Content-Length", "71", "Cookie", cookie));
		req1 = http_last_sent_request();
		ssl_req1 = https_req_get(port:port , request:req);
		if( ssl_req1 == NULL) exit(0);
		con = req1 + ssl_req1;
		if( "302 Found">< ssl_req1 && "location: dmframe.php" >< ssl_req1){
			if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
		}
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