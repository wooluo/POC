include("compat.inc");


if (description)
{
  script_id(51799273);
  script_version("1.3");
  script_name(english:"kedacom camera detect");
  script_summary(english:"kedacom camera detect");
  script_set_attribute(attribute:"description", value:"kedacom camera datect.");
  script_set_attribute(attribute:"solution", value:"None");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Camera");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  
  script_dependencies("http_version.nasl");
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
	url_ipc = string('/kdsapi/system/deviceinfo');
	url_nvr = string('/index_cn.htm');
	req = http_send_recv3(method: "GET", port: port, item: url_ipc,exit_on_fail:0);
	if("200 O">< req[0] && "</devicetype>" >< req[2] && "</softversion>" >< req[2]){
		devicetype = eregmatch(pattern: '.*<devicetype>(.*)</devicetype>', string: req[2], icase: 0);
		softversion = eregmatch(pattern: '.*<softversion>(.*)</softversion>', string: req[2], icase: 0);
		set_kb_item(name:"kedacom_ipc",value:port);
		security_hole(port:port, data:"kedacom IPC CAMREA " + devicetype[1] + "   Version: " + softversion[1]);

    }
	if("200 O">!< req[0]){
		req_nvr = http_send_recv3(method: "GET", port: port, item: url_nvr,exit_on_fail:0);
		if("200 O">< req_nvr[0] && ('nvr_station Web</title>' >< req_nvr[2] || 'NVR Station Web</title>' >< req_nvr[2]) && "NVRStationSetup_web.exe" >< req_nvr[2]){
			security_hole(port:port, data:"kedacom NVR CAMREA Find !");	
		}
	}
}


####################
#begin here
####################
port = get_kb_item("Services/www");
if(!isnull(port)){
	check_vuln(port:port);
}
exit(0);
