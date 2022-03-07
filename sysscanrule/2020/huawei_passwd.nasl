#
# 

include("compat.inc");


if (description)
{
  script_id(51799263);
  script_version("1.11");

  script_name(english:"Huawei camera weak password vulnerability");
  script_summary(english:"Huawei camera weak password vulnerability");

  script_set_attribute(attribute:"synopsis", value:"Detecting the presence of the camera head Huawei default password or a weak password vulnerability.");
  script_set_attribute(attribute:"description", value:"Detecting the presence of the camera head Huawei default password or a weak password vulnerability.");
  script_set_attribute(attribute:"solution", value:"Change the password strength of the camera.");

  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Camera");

  script_copyright(english:"This script is Copyright (C) 2009-2018 Webray Security, Inc.");

  script_dependencies("huawei_camera_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");



if(get_kb_item("hw_ipc_ssl")){
	send_port = get_kb_item("hw_ipc_sslport");
	if(isnull(send_port))exit(0);
	referer = get_kb_item("hw_ipc_sslrefer");
	check_ssl(port:send_port,refer:referer);

}else{

	send_port = get_kb_item("hw_ipc_port");
	if(isnull(send_port))exit(0);
	referer = get_kb_item("hw_ipc_refer");
	check(port:send_port,refer:referer);

}




function check_ssl(port,refer){
	#passwords = make_list("HuaWei123");
	passwords = make_list("HuaWei123","Admin@123","huawei@123");
	foreach password (passwords){
		url = "/cgi-bin/main.cgi";
		getcookie_data = "action=LoginState&glToken=null&para= ";
		var cookie_req =
			'POST ' + url +' HTTP/1.1\r\n' +
			'Host: ' + get_host_ip() + ":" +port+ '\r\n' +
			'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0' + '\r\n' +
			'Accept-Encoding: gzip, deflate' + '\r\n' +
			'Content-Type: application/x-www-form-urlencoded' + '\r\n' +
			'Referer: '+refer + '\r\n' +
			'Connection: keep-alive'+ '\r\n' +
			'Accept: */*' + '\r\n' + 
			'Content-Length: 37' + '\r\n' + 
			'\r\n'+
			getcookie_data;
		ssl_cookie_req = https_req_get(port:port, request:cookie_req);
		if("200 OK" >< ssl_cookie_req && "Set-Cookie" >< ssl_cookie_req){
			cookie = eregmatch(pattern:'Set-Cookie: *(sessionid([0-9a-zA-Z=_])+;)', string:ssl_cookie_req);		
		}
		
		
		data = "action=WebGetPwdSalt&username=admin&glToken=&para= ";
		var req =
			'POST ' + url +' HTTP/1.1\r\n' +
			'Host: ' + get_host_ip() + ":" +port+ '\r\n' +
			'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0' + '\r\n' +
			'Accept-Encoding: gzip, deflate' + '\r\n' +
			'Content-Type: application/x-www-form-urlencoded' + '\r\n' +
			'Referer: '+refer + '\r\n' +
			'Cookie: language=0; '+ cookie[1]+ '\r\n' +
			'Connection: keep-alive'+ '\r\n' +
			'Accept: */*' + '\r\n' + 
			'Content-Length: 51' + '\r\n' + 
			'\r\n'+
			data;
		ssl_req = https_req_get(port:port, request:req);
		if ("PASSWORDRANDOM" >< ssl_req && "PASSWORDSALT" >< ssl_req ){
			random_salt = eregmatch(pattern:'{"PASS.*', string:ssl_req);
			pwdRandom = substr(random_salt[0],19, 83);
			pwdSaltValue = substr(random_salt[0],101, 165);
			

			step1 = hexstr(SHA256("admin"+password));

			for (var b = 0; b < strlen(pwdSaltValue); b++) {
				var f = substr(pwdSaltValue, b, b+1);
				if (f[0] == "0"){
					step1 = substr(step1,0, b-1) + "0" + substr(step1,b + 1, strlen(step1));
				}
			}
			step2 = hexstr(SHA256(step1));
			
			pass_data = "action=WebLogin&username=admin&password="+step2+"&captcha=NULL&glToken=null&para=";
			var res =
				'POST ' + url +' HTTP/1.1\r\n' +
				'Host: ' + get_host_ip() + ":" +port+ '\r\n' +
				'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0' + '\r\n' +
				'Accept-Encoding: gzip, deflate' + '\r\n' +
				'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' + '\r\n' +
				'Referer: '+refer + '\r\n' +
				'Cookie: language=0; '+ cookie[1]+ '\r\n' +
				'Connection: keep-alive'+ '\r\n' +
				'Content-Length: 137' + '\r\n' + 
				'Accept: */*' + '\r\n' + 
				'\r\n'+
				pass_data;
			pass_data = https_req_get(port:port , request:res);
			if ("200 OK">< pass_data&& "LOGIN_SUCCESS" >< pass_data){
				security_hole(port:port,data:"admin:"+password);
				exit(0);
			}
		}
	}
}

function check(port,refer){
	passwords = make_list("HuaWei123","Admin@123","huawei@123");
	foreach password (passwords){
		urls = "/cgi-bin/main.cgi";
		
		getcookie_data = "action=LoginState&glToken=null&para= ";
		cookie_res = http_send_recv3(method:"POST", item:urls, port:port, data:getcookie_data,add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8","Referer",refer,"Content-Length",strlen(getcookie_data)),exit_on_fail: 1);
		if("200 OK" >< cookie_res[0] && "Set-Cookie" >< cookie_res[1]){
			cookie = eregmatch(pattern:'Set-Cookie: *(sessionid([0-9a-zA-Z=_])+;)', string:cookie_res[1]);		
		}
		
		
		data = "action=WebGetPwdSalt&username=admin&glToken=&para= ";
		res = http_send_recv3(method:"POST", item:urls, port:port, data:data,add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8","Referer",refer,"Content-Length",strlen(data),"Cookie","language=0; "+cookie[1]),exit_on_fail: 1);
		if ("PASSWORDRANDOM" >< res[2] && "PASSWORDSALT" >< res[2] ){
			pwdRandom = substr(res[2],19, 83);
			pwdSaltValue = substr(res[2],101, 165);
			
			step1 = hexstr(SHA256("admin"+password));
			
			for (b = 0; b < strlen(pwdSaltValue); b++) {
				var f = substr(pwdSaltValue, b , b + 1);
				if (f[0] == "0") {
					step1 = substr(step1,0, b-1) + "0" + substr(step1,b + 1, strlen(step1));
				}
			}
			step2 = hexstr(SHA256(step1));
			
			pass_data = "action=WebLogin&username=admin&password="+step2+"&captcha=NULL&glToken=null&para=";
			res_way = http_send_recv3(method:"POST", item:urls, port:port, data:pass_data,add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8","Referer",refer,"Content-Length",strlen(pass_data),"Cookie","language=0; "+cookie[1]),exit_on_fail: 1);
			if ("200 OK">< res_way[0] && "LOGIN_SUCCESS" >< res_way[2]) {
				security_hole(port:port,data:"admin:"+password);
				exit(0);
			}
		}
	}
}

exit(0, "The web server on port "+port+" is not affected.");
