#
#
#

include("compat.inc");


if (description)
{
  script_id(51799264);
  script_version("1.11");
  script_name(english:"Hikvision camera weak password vulnerability 1");
  script_summary(english:"Hikvision camera weak password vulnerability 1");

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
	time = gettime();
	usec = string(time['usec']);
	timeStamp = time['sec'] + usec[0]+ usec[1]+usec[2];
	urls = "/ISAPI/Security/userCheck?timeStamp="+timeStamp;
	res = http_send_recv3(method:"GET", item:urls, port:port, exit_on_fail: 0);
	if (res[0] =~ "^HTTP/1\.[01] 401 " && egrep(pattern:'^WWW-Authenticate: *Digest.* realm="[^"]+"', string:res[1])){
		realm = eregmatch(pattern:'WWW-Authenticate: *Digest.*realm="([0-9a-zA-Z-_]+)"', string:res[1]);
		nonce = eregmatch(pattern:'WWW-Authenticate: *Digest.*nonce="([0-9a-zA-Z-_:]+)"', string:res[1]);
		qop   = eregmatch(pattern:'WWW-Authenticate: *Digest.*qop="([0-9a-zA-Z-_:]+)"', string:res[1]);
		ha1 = hexstr(MD5("admin" + ":" + realm[1] + ":"+ password));
		ha2 = hexstr(MD5("GET" + ":" + urls));
		hnc = hexnumber(n: 1);
		resp = hexstr(MD5(ha1 + ':' + nonce[1] + ':' + hnc + ':' + timeStamp + ':' + qop[1] + ':' + ha2));  # timeStamp = cnonce
		username = "admin";
		
		authR = 'Digest username="' + username + '", realm="' + realm[1] +
              '", nonce="' + nonce[1] + '", uri="' + urls + '", algorithm=' +
              'MD5' + ', response="' + resp + '", qop=' + qop[1] + ', nc=' +
              hnc + ', cnonce="' + timeStamp + '"';

			  
		res_way = http_send_recv3(method:'GET', item:urls, port:port,  add_headers:make_array("Authorization",authR) ,exit_on_fail:TRUE);
		if ("200 OK">< res_way[0] && "<statusValue>200</statusValue>" >< res_way[2] && "<statusString>OK</statusString>" >< res_way[2]){
			security_hole(port:port,data:"admin:"+password);
			exit(0);
		}
	}
}


exit(0, "The web server on port "+port+" is not affected.");
