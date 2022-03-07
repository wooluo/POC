##达梦数据库存在任意文件删除漏洞

include("compat.inc");
if(description)
{
 script_id(51799158);
 script_category(ACT_GATHER_INFO);
 script_family("CNDB");
 script_version("$Revision: 13 $");
 script_name(english:"Dameng DB Arbitrary file deletion vulnerability");
 script_set_attribute(attribute:"description", value:"Dameng database has an arbitrary file deletion vulnerability. Allow ordinary users to delete all system tablespace files, control files, and other important files through the SP_WORD_LIB_DELETE function, causing the database to fail to start.");
 script_set_attribute(attribute : "solution" , value : "The latest version confirms that this vulnerability has been fixed, and users are recommended to download and use:http://www.dameng.com/");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:P");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_dependencies("gb_dameng_detect.nasl");
 script_copyright(english:"This script is Copyright (C) 2017 WebRAY, Inc.");
 exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

dameng_port = get_kb_item("dameng_port");
dameng_version = get_kb_item("dameng_version_"+dameng_port);
if( dameng_version =~ "^7\.1\." && ver_compare(ver:dameng_version,fix:"7.1.5.158",strict:FALSE)<= 0)
{
	set_kb_item(name:"dameng_version_158_"+dameng_port,value:dameng_version);
	set_kb_item(name:"dameng_port_158",value:dameng_port);
	security_hole(port:dameng_port,data:dameng_version);
}
exit();