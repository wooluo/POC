#
#
#

include("compat.inc");


if (description)
{
  script_id(51799265);
  script_version("1.11");
  script_name(english:"Hikvision camera weak password vulnerability 2");
  script_summary(english:"Hikvision camera weak password vulnerability 2");

  script_set_attribute(attribute:"synopsis", value:"Detecting the presence of the camera head Hikvision default password or a weak password vulnerability.");
  script_set_attribute(attribute:"description", value:"Detecting the presence of the camera head Hikvision default password or a weak password vulnerability.");
  script_set_attribute(attribute:"solution", value:"Change the password strength of the camera.");

  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Camera");
  script_copyright(english:"This script is Copyright (C) 2009-2018 Webray Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

passwords = make_list("test@123","admin123","admin@123","Admin123","Admin@123","webrey603");
foreach password (passwords){
	urls = "/ISAPI/Security/sessionLogin/capabilities?username=admin";
	url_login = "/ISAPI/Security/sessionLogin?username=admin";
	res = http_send_recv3(method:"GET", item:urls, port:port, exit_on_fail: 1);
	if ("200 OK" >< res[0]&& "</salt>" >!< res[2] && "</challenge>" >< res[2]){
		sessionID = eregmatch(pattern:'<sessionID>(.*)</sessionID>', string:res[2]);
		challenge = eregmatch(pattern:'<challenge>(.*)</challenge>', string:res[2]);
		iterations = eregmatch(pattern:'<iterations>(.*)</iterations>', string:res[2]);
		l = hexstr(SHA256(password)) + challenge[1];
		for ( m = 1; iterations[1] > m; m++) l = hexstr(SHA256(l));	  
		data = "<SessionLogin><userName>admin</userName><password>"+l+"</password><sessionID>"+sessionID[1]+"</sessionID></SessionLogin>";
		
		res_way = http_send_recv3(method:'POST', item:url_login, port:port, data:data,exit_on_fail:TRUE);
		if ("200 OK">< res_way[0] && "<statusValue>200</statusValue>" >< res_way[2] && "<statusString>OK</statusString>" >< res_way[2]){
			security_hole(port:port,data:"admin:"+password);
			exit(0);
		}
	}
	
	if ("200 OK" >< res[0]&& "</salt>" >< res[2] && "</challenge>" >< res[2]){
		sessionID = eregmatch(pattern:'<sessionID>(.*)</sessionID>', string:res[2]);
		challenge = eregmatch(pattern:'<challenge>(.*)</challenge>', string:res[2]);
		iterations = eregmatch(pattern:'<iterations>(.*)</iterations>', string:res[2]);
		isIrreversible = eregmatch(pattern:'<isIrreversible>(.*)</isIrreversible>', string:res[2]);
		salt = eregmatch(pattern:'<salt>(.*)</salt>', string:res[2]);
		if("true" >< isIrreversible[1]){
			a = hexstr(SHA256("admin" + salt[1] + password));
			a = hexstr(SHA256(a + challenge[1]));
			for (var n = 2; iterations[1] > n; n++) a = hexstr(SHA256(a));
		
		}else{
			a = hexstr(SHA256(password)) + challenge[1];
			for (var n = 1; iterations[1] > n; n++) a = hexstr(SHA256(a));
		
		}
		data = "<SessionLogin><userName>admin</userName><password>"+a+"</password><sessionID>"+sessionID[1]+"</sessionID></SessionLogin>";
		res_way = http_send_recv3(method:'POST', item:url_login, port:port, data:data,exit_on_fail:TRUE);
		if ("200 OK">< res_way[0] && "<statusValue>200</statusValue>" >< res_way[2] && "<statusString>OK</statusString>" >< res_way[2]){
			security_hole(port:port,data:"admin:"+password);
			exit(0);
		}
	}
	
	
}


exit(0, "The web server on port "+port+" is not affected.");
