include("compat.inc");


if (description)
{
  script_id(51799270);
  script_version("1.3");
  script_name(english:"kedacom camera default password detect");
  script_summary(english:"kedacom camera default password detect");
  script_set_attribute(attribute:"description", value:"kedacom camera default password detect.");
  script_set_attribute(attribute:"solution", value:"None");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Camera");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  
  script_dependencies("kedacom_camera_detect.nasl");
  script_require_ports("Services/www", 80, 443);
  exit(0);
}


############################################
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("json.inc");
include("openvas-https2.inc");


function check_vuln(port){
	url_pre_ipc = string('/kdsapi/link/authenticationid');
	url_ipc = string('/kdsapi/security/login');
	req = http_send_recv3(method: "GET", port: port, item: url_pre_ipc,exit_on_fail:0);
	if("200 O">< req[0] && "</authenticationid>" >< req[2]){
		auid = eregmatch(pattern: '.*<authenticationid>(.*)</authenticationid>', string: req[2], icase: 0);
		if(isnull(auid[1])) exit(0);
		
		passwd = base64(str:hexstr(MD5("admin"+","+"admin123"+","+auid[1])));
		data = '<contentroot><authenticationinfo type="7.0"><username>admin</username><password>'+passwd+'</password><authenticationid>'+auid[1]+'</authenticationid></authenticationinfo><loginparam version="1.0" xmlns="http://www.kedacom.com/ver10/XMLSchema"/></contentroot>';
		
		passwd_req = http_send_recv3(method: "POST", port: port, data:data, item: url_ipc,exit_on_fail:0);
		if("200 O">< passwd_req[0] && "<statusstring>success</statusstring>" >< passwd_req[2] && "OK</substatusstring>" >< passwd_req[2]){
			security_hole(port:port, data:"kedacom IPC CAMREA Default Account/Password : admin/admin123");
		}
    }
}

####################
#begin here
####################
port = get_kb_item("kedacom_ipc");
if(!isnull(port)){
	check_vuln(port:port);
}
exit(0);
