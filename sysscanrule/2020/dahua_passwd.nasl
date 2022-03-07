#
# 

include("compat.inc");


if (description)
{
  script_id(51799268);
  script_version("1.11");

  script_name(english:"dahua camera weak password vulnerability");
  script_summary(english:"dahua camera weak password vulnerability");

  script_set_attribute(attribute:"synopsis", value:"Detecting the presence of the camera head dahua default password or a weak password vulnerability.");
  script_set_attribute(attribute:"description", value:"Detecting the presence of the camera head dahua default password or a weak password vulnerability.");
  script_set_attribute(attribute:"solution", value:"Change the password strength of the camera.");

  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Camera");

  script_copyright(english:"This script is Copyright (C) 2009-2018 Webray Security, Inc.");

  script_dependencies("dahua_camera_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("json.inc");
include("openvas-https2.inc");


port = get_kb_item("Services/www");
ssl_port = get_kb_list("SSL/Transport"+port);
if(!ssl_port){
	check(port:port);
}else{
	check_ssl(port:port);
}


function check_ssl(port){
	passwords = make_list("admin","Admin@123","888888","test@123");
	foreach password (passwords){
		url = "/RPC2_Login";
		num = num+1;
		getcookie_data = '{"method":"global.login","params":{"userName":"admin","password":"","clientType":"Web3.0"},"id":'+num+'}';
		var cookie_req =
			'POST ' + url +' HTTP/1.1\r\n' +
			'Host: ' + get_host_ip() + ":" +port+ '\r\n' +
			'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0' + '\r\n' +
			'Accept-Encoding: gzip, deflate' + '\r\n' +
			'Content-Type: application/x-www-form-urlencoded' + '\r\n' +
			'Connection: keep-alive'+ '\r\n' +
			'X-Requested-With: XMLHttpRequest'+ '\r\n' +
			'X-Request: JSON'+ '\r\n' +
			'Accept: */*' + '\r\n' + 
			'Content-Length: ' + strlen(getcookie_data) + '\r\n' + 
			'\r\n'+
			getcookie_data;
		ssl_cookie_req = https_req_get(port:port, request:cookie_req);
		if("200 OK" >< ssl_cookie_req && '"error"' >< ssl_cookie_req){
			cookie = eregmatch(pattern:'"error".*', string:ssl_cookie_req);
			prefs = json_read("{"+cookie[0]);
			realm = prefs[0]['params']['realm'];
			random = prefs[0]['params']['random'];
			encryption = prefs[0]['params']['encryption'];
			id = prefs[0]['id'];
			session = prefs[0]['session'];
		}
		
		if ("efault" >< encryption ){
			if(isnull(random) || isnull(realm)) exit(0);
		
			enc_passwd = toupper(hexstr(MD5("admin"+":"+realm+":"+password)));
			enc_passwd = toupper(hexstr(MD5("admin"+":"+random+":"+enc_passwd)));
			if(isnull(session)) exit(0);
			if(strlen(session) < 15){
				passwd_data = '{"method":"global.login","session":'+session+',"params":{"userName":"admin","password":"'+enc_passwd+'","clientType":"Web3.0"},"id":'+id+'}';
			}
			else{		
				passwd_data = '{"method":"global.login","params":{"userName":"admin","password":"'+enc_passwd+'","clientType":"Dahua3.0-Web3.0-NOTIE","authorityType":"Default","passwordType":"Default"},"id"'+id+',"session":"'+session+'"}';		
			}
			
			var res =
				'POST ' + url +' HTTP/1.1\r\n' +
				'Host: ' + get_host_ip() + ":" +port+ '\r\n' +
				'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0' + '\r\n' +
				'Accept-Encoding: gzip, deflate' + '\r\n' +
				'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' + '\r\n' +
				'Connection: keep-alive'+ '\r\n' +
				'X-Requested-With: XMLHttpRequest'+ '\r\n' +
				'X-Request: JSON'+ '\r\n' +
				'Content-Length: ' + strlen(passwd_data) +'\r\n' + 
				'Accept: */*' + '\r\n' + 
				'\r\n'+
				passwd_data;
				pass_data = https_req_get(port:port , request:res);
			if ("200 OK">< pass_data && '"result"' >< pass_data&&"true," >< pass_data){
				security_hole(port:port,data:"admin:"+password);
				exit(0);
			}
		}
		
	}
}

function check(port){
	passwords = make_list("admin","Admin@123","888888","test@123");
	foreach password (passwords){urls = "/RPC2_Login";
		num = num+1;
		getcookie_data = '{"method":"global.login","params":{"userName":"admin","password":"","clientType":"Web3.0"},"id":'+num+'}';
		cookie_res = http_send_recv3(method:"POST", item:urls, port:port, data:getcookie_data,add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8","Content-Length",strlen(getcookie_data)),exit_on_fail: 1);
		
		if("200 OK" >< cookie_res[0]){
			prefs = json_read(cookie_res[2]);
			realm = prefs[0]['params']['realm'];
			random = prefs[0]['params']['random'];
			encryption = prefs[0]['params']['encryption'];
			id = prefs[0]['id'];
			session = prefs[0]['session'];
		}
		if ("efault" >< encryption ){
			if(isnull(random) || isnull(realm)) exit(0);
			
			enc_passwd = toupper(hexstr(MD5("admin"+":"+realm+":"+password)));
			enc_passwd = toupper(hexstr(MD5("admin"+":"+random+":"+enc_passwd)));
			if(isnull(session)) exit(0);
			if(strlen(session) < 15){
				passwd_data = '{"method":"global.login","session":'+session+',"params":{"userName":"admin","password":"'+enc_passwd+'","clientType":"Web3.0"},"id":'+id+'}';
			}
			else{		
				passwd_data = '{"method":"global.login","params":{"userName":"admin","password":"'+enc_passwd+'","clientType":"Dahua3.0-Web3.0-NOTIE","authorityType":"Default","passwordType":"Default"},"id"'+id+',"session":"'+session+'"}';		
			}
			login_res = http_send_recv3(method:"POST", item:urls, port:port, data:passwd_data,add_headers:make_array("X-Requested-With"," XMLHttpRequest","X-Request","JSON", "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8","Content-Length",strlen(passwd_data)),exit_on_fail: 0);
			if("200 OK" >< login_res[0] && '"result"' >< login_res[2]&&"true," >< login_res[2]){
				security_hole(port:port,data:"admin:"+password);
			}
		}
	}

}
exit(0, "The web server on port "+port+" is not affected.");
