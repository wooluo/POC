############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");


if(description)
{
 script_id(51799057);
 name = "Sony Webcam - unauthorized access";
 script_name(name);
 script_category(ACT_ATTACK);
 script_family(english:"Camera");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_set_attribute(attribute:"risk_factor", value:"Medium");
 script_set_attribute(attribute:"description", value:"The Sony webcam has unauthorized access. Anyone can access the background management page to view the video content directly, which violates the user's privacy and security, but does not have the right to modify the configuration and other malicious operations.");
 script_set_attribute(attribute:"solution", value:"1. Limited directory. 2. The white list restricts the readable path. 3. Add password, preferably more than 8 digits, including upper and lower case letters, numbers and special characters.");
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
	url1 = string("/home/homeS.html");
	url2 = string("/index.html");
	url3 = string("/en/index.html");
	re1 = http_get(item:url1, port:port);
	re2 = http_get(item:url2, port:port);
	re3 = http_get(item:url3, port:port);
	req1 = http_keepalive_send_recv(port:port,data:re1,bodyonly:FALSE);
	req2 = http_keepalive_send_recv(port:port,data:re2,bodyonly:FALSE);
	req3 = http_keepalive_send_recv(port:port,data:re3,bodyonly:FALSE);
	if( req1 == NULL && req2 == NULL && req3 == NULL) exit(0);
	con = re1 + req1 + re2 + req2 + re3 + req3;
	if(("200 ">< req1 && "SViewer.html" >< req1 ) || ("200 ">< req2 && "Live" >< req2 && "Setting" >< req2 && "viewerPageBox" >< req2) || ("200 ">< req3 && 'onload="contentsFrameLoaded(this)' >< req3 && 'onload="changeInitialFrame' >< req3 && 'frame id="id_viewer" name="contentFrame' >< req3)){
	  	if (report_verbosity > 0) security_hole(port:port, extra:con);
			  else security_hole(port);
    }
}

function check_vuln_ssl(port){
	url1 = string("/home/homeS.html");
	url2 = string("/index.html");
	url3 = string("/en/index.html");
	req1 = http_get(item:url1, port:port);
	req2 = http_get(item:url2, port:port);
	req3 = http_get(item:url3, port:port);
	ssl_req1 = https_req_get(port:port,request:req1);
	ssl_req2 = https_req_get(port:port,request:req2);
	ssl_req3 = https_req_get(port:port,request:req3);
	if( ssl_req1 == NULL && ssl_req2 == NULL && ssl_req3 == NULL) exit(0);
	con = req1 + ssl_req1 + req2 + ssl_req2 + req3 + ssl_req3;
	if(("200 ">< ssl_req1 && "SViewer.html" >< ssl_req1) || ("200 ">< ssl_req2 && "Live" >< ssl_req2 && "Setting" >< ssl_req2 && "viewerPageBox" >< ssl_req2) || ("200 ">< ssl_req3 && 'onload="contentsFrameLoaded(this)' >< ssl_req3 && 'onload="changeInitialFrame' >< ssl_req3 && 'frame id="id_viewer" name="contentFrame' >< ssl_req3)){
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
