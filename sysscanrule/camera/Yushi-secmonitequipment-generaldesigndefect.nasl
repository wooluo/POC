############################################################
# Author: ox50sec@webray.com.cn
# Copyright @WebRAY
############################################################
include("compat.inc");

if (description)
{
 script_id(51799031);
 name = "Zhejiang Yushi large number of security monitoring equipment - general design defect (root authority)";
 script_name(name);
 script_category(ACT_ATTACK);
 script_set_attribute(attribute:"description", value:"A large number of security monitoring devices of Zhejiang Yushi have common design defects, which can obtain root authority.");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"solution", value:"Change default password and increase password strength.");
 script_end_attributes();
 script_copyright("This script is Copyright (c) 2015 WebRAY");
 script_family(english:"Camera");
 script_dependencies("DDI_FTP_Any_User_Login.nasl", "ftpserver_detect_type_nd_version.nasl","ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include('global_settings.inc');
include('misc_func.inc');
include('ftp_func.inc');


port = get_ftp_port(default: 21);
soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

data = get_kb_item("ftp/banner/"+port);

if("No anonymous login" >< data){
	if ( ftp_authenticate(socket:soc, user:"root",pass:"passwd") || ftp_authenticate(socket:soc, user:"downloadusr",pass:"h3ckey")){
		security_hole(port:port,data:"root:passwd OR downloadusr:h3ckey");
	}
}
ftp_close(socket: soc);
