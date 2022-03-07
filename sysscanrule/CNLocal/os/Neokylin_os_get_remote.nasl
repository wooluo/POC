###############################################################################
# yangxu 检测到目标主机运行着中标麒麟操作系统 219.141.211.80
###############################################################################


if(description)
{
  script_id(51799176);
  script_version("$Revision: 13 $");
  script_name(english:"Check NeoKylin OS");
  script_summary(english:"Check NeoKylin working");
  script_copyright(english:"This script is Copyright (C) 2017 WebRAY, Inc.");
  script_category(ACT_GATHER_INFO);
  script_set_attribute(attribute:"risk_factor", value:"Low");
  script_family("CNLocal");
  script_dependencies("http_version.nasl","telnet_clear_text.nasl");
  script_require_ports("Services/telnet", "Services/www",23,80);
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
port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);
if (!get_port_state(port)) exit(0);
issue = get_kb_item("Services/telnet/banner/" + port);
if ("NeoKylin Linux" >< issue && "Kernel" >< issue)
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
	if(  strlen(banner[0]) > 5 && ("(NeoKylin" >< banner[0] || "(neokylin" >< banner[0] )) {
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
	if(strlen(banner[0]) > 5 && ( "(NeoKylin" >< banner[0] || "(neokylin" >< banner[0]  )){
		if (report_verbosity > 0) security_hole(port:port, extra:req+ssl_req);
			  else security_hole(port);
	}
}


exit(0);
