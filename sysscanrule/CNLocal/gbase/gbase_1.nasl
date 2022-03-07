##南大通用GBASE数据库存在拒绝服务漏洞   CNVD-2016-09750 

include("compat.inc");
if(description)
{
 script_id(51799185);
 script_category(ACT_ATTACK);
 script_family("CNDB");
 script_version("$Revision: 13 $");
 script_name(english:"GBASE database has a denial of service vulnerability");
 script_set_attribute(attribute:"description", value:"There is a denial-of-service vulnerability in the version 8.3 of NTU's GBASE database. Any user calls the astest function after logging in to gbase with specific parameters. Eventually it will cause GBASE to run out of memory and go down. Allow attackers to exploit this vulnerability leading to denial of service.");
 script_set_attribute(attribute : "solution" , value : "The latest version confirms that this vulnerability has been fixed, and users are recommended to download and use: http://www.gbase.cn/ ");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_dependencies("gbase_detect.nasl");
 script_set_attribute(attribute:"risk_factor", value:"Medium");
 script_copyright(english:"This script is Copyright (C) 2017 WebRAY, Inc.");
 exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

gbase_port = get_kb_item("Gbase_port");
gbase_version = get_kb_item("Gbase_version_"+gbase_port);
if( gbase_version =~ "^8\.3\.")
{
	security_hole(port:dameng_port,data:gbase_version);
}
exit();