############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799090);
 name = "Intellinet Professional Network IP Camera - default password";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"description", value:"Intellinet Professional Network IP Camera, The default password of professional webcam allows attackers to log into the background directly, view camera content, modify camera configuration, even control the entire device, and disclose user privacy.");
 script_set_attribute(attribute:"solution", value:"1. Limited directory. 2. The white list restricts the readable path. 3. Set the password with more than 8 digits, preferably including upper and lower case letters, numbers and special characters.");
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
	buf1 = http_get_cache(port:port, item:"/indexSubmit.cgi?Mode=ActiveX&ID=admin&PassWord=admin&x=31&y=15");  
	buf2 = http_get_cache(port:port, item:"/indexSubmit.cgi?Mode=ActiveX&ID=guest&PassWord=guest&x=31&y=15");
    if( buf1 == NULL && buf2 == NULL) exit(0);
	con = buf1 + buf2;
	if( ("200 O"><buf1 && "./main_activex.cgi"><buf1) || ("200 O"><buf2 && "./main_activex.cgi"><buf2) ){
		if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){

	url1 = string("/indexSubmit.cgi?Mode=ActiveX&ID=admin&PassWord=admin&x=31&y=15");
	req1 = http_get(item:url1, port:port);
	ssl_req1 = https_req_get(port:port,request:req1);
	url2 = string("/indexSubmit.cgi?Mode=ActiveX&ID=guest&PassWord=guest&x=31&y=15");
	req2 = http_get(item:url2, port:port);
	ssl_req2 = https_req_get(port:port,request:req2);
	url3 = string("/loginSubmit.cgi?Mode=Applet&ID=admin&PassWord=admin&x=30&y=16");
	req3 = http_get(item:url3, port:port);
	ssl_req3 = https_req_get(port:port,request:req3);
	url4 = string("/loginSubmit.cgi?Mode=Applet&ID=guest&PassWord=guest&x=30&y=16");
	req4 = http_get(item:url4, port:port);
	ssl_req4 = https_req_get(port:port,request:req4);
	if( ssl_req1 == NULL && ssl_req2 == NULL) exit(0);
	con = req1 + ssl_req1 + req2 + ssl_req2 + req3 + ssl_req3 + req4 + ssl_req4;
	if( ("200 O"><ssl_req1 && "./main_activex.cgi"><ssl_req1) || ("200 O"><ssl_req2 && "./main_activex.cgi"><ssl_req2) || ("200 O"><ssl_req3 && "./monitoring.cgi"><ssl_req3) || ("200 O"><ssl_req4 && "./monitoring.cgi"><ssl_req4)){
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
