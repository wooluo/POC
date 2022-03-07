############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799151);
 name = "Basler camera - weak password";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"description", value:"Basler camera weak password.");
 script_set_attribute(attribute:"solution", value:"Increase password strength");
 script_end_attributes();
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
	host1 = get_host_name( );
	if( port==80 ) host=host1;
    else host = string(host1,":",port);

	req = 'POST /cgi-bin/auth_if.cgi?Login HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
	  'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n' +
	  'Accept: */*\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'X-Requested-With: XMLHttpRequest\r\n' +
      'Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n' +
	  'Content-Length: 39\r\n' +
	  'Origin: http://' + host + '\r\n' +
	  'Connection: close\r\n' +
	  'Referer: http://' + host + '/webapp/\r\n\r\n' +
	  'Auth.Username=admin&Auth.Password=admin';
     
	buf = http_keepalive_send_recv(port:port,data:req,bodyonly:FALSE);
	if( buf == NULL) exit(0);
	con = req + buf;
	if( "200 "><buf && ( "success: true"><buf || "reason: 'Success',"><buf || "json_valid: true"><buf )){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
	if ( !get_port_state(port) ) exit(0);
	host1 = get_host_name( );
	if( port==443 ) host=host1;
    else host = string(host1,":",port);

	req = 'POST /cgi-bin/auth_if.cgi?Login HTTP/1.1\r\n' +
	  'Host: ' + host + '\r\n' +
	  'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n' +
	  'Accept: */*\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'X-Requested-With: XMLHttpRequest\r\n' +
      'Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n' +
	  'Content-Length: 39\r\n' +
	  'Origin: https://' + host + '\r\n' +
	  'Connection: close\r\n' +
	  'Referer: https://' + host + '/webapp/\r\n\r\n' +
	  'Auth.Username=admin&Auth.Password=admin';
    
	ssl_req = https_req_get(port:port,request:req);
	if( ssl_req == NULL) exit(0);
	con = req + ssl_req;
	if( "200 "><ssl_req && ( "success: true"><ssl_req || "reason: 'Success',"><ssl_req || "json_valid: true"><ssl_req )){
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