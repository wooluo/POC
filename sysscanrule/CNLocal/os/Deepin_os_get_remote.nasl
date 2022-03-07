###############################################################################
# yangxu 检测到目标主机运行着深度操作系统 219.141.211.80
###############################################################################


if(description)
{
  script_id(51799177);
  script_version("$Revision: 13 $");
  script_name(english:"Check Deepin OS");
  script_summary(english:"Check Deepin working");
  script_copyright(english:"This script is Copyright (C) 2017 WebRAY, Inc.");
  script_category(ACT_GATHER_INFO);
  script_set_attribute(attribute:"risk_factor", value:"Low");
  script_family("CNLocal");
  script_dependencies("http_version.nasl","ssh_detect.nasl","find_service1.nasl","find_service2.nasl");
  script_require_ports("Services/ssh", "Services/www", "Services/redis",22,80,6379);
  exit(0);
}


include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");
include("telnet2_func.inc");
include("audit.inc");
include("http.inc");
include("openvas-https2.inc");

cmdline = 0;
port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
if (!get_port_state(port)) exit(0);
issue = get_kb_item("SSH/banner/" + port);
if ("deepin" >< issue && "Deepin" >< issue)
{
	security_hole(port:port,data:issue);
}


##################################
ver = "";

wport = get_kb_item("Services/www");
if(!wport)exit(0);

ssl = get_kb_list("SSL/Transport/"+wport);
if(!ssl) {
	check_vuln(port:port);
} else {
	check_vuln_ssl(port:port);
}


function check_vuln(port){
	url = string("/");
	req = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0"));
	banner = eregmatch(pattern:"Server.*",string:req[1]);
	if(strlen(banner[0]) > 5 && ("(Deepin" >< banner[0] || "(deepin" >< banner[0] )) {
		if (report_verbosity > 0) security_hole(port:port, extra:req[1]);
			  else security_hole(port);
	}
}

function check_vuln_ssl(port){
	url = string("/");
	res = http_send_recv3(method: "GET", port: port, item: url, add_headers: make_array("User_Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0"));
        req = http_last_sent_request();
	ssl_req = https_req_get(port:port , request:req);
	banner = eregmatch(pattern:"Server.*",string:ssl_req);
	if(strlen(banner[0]) > 5 && ("(Deepin" >< banner[0] || "(deepin" >< banner[0] )){
		if (report_verbosity > 0) security_hole(port:port, extra:req+ssl_req);
			  else security_hole(port);
	}
}



redis_port = get_kb_item("Services/redis");
if(!redis_port)exit(0);
if(get_port_state(redis_port)){
	req = raw_string(0x69, 0x6e, 0x66, 0x6f, 0x0d, 0x0a);
	soc = open_sock_tcp(redis_port);
	if(!soc){
	 exit(0);
	}
	send(socket:soc, data:req);
	buf = recv(socket:soc, length:1024);
	os_banner = eregmatch(pattern:"os:.*",string:buf);
	if(strlen(os_banner[0]) > 5 && ("Deepin" >< os_banner[0] || "deepin" >< os_banner[0] )){
		if (report_verbosity > 0) security_hole(port:port, extra:buf);
			  else security_hole(port);
	}

}


exit(0);
