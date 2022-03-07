##达梦数据库服务器存在越权访问漏洞

include("compat.inc");

if(description)
{
 script_id(51799162);
 script_category(ACT_GATHER_INFO);
 script_family("CNDB");
 script_name(english:"Dameng DB Unauthorized modification process vulnerability");
 script_set_attribute(attribute:"description", value:"Dameng database has an unauthorized access vulnerability. When the DM7 database calls an external dynamic library, it lacks restrictions on the path to the reference dynamic library. An attacker with an arbitrary account on the operating system and a DBA account on the operating system can use the vulnerability to gain permissions equivalent to the Dameng account on the operating system, and even crash the Dameng database process, causing the database to shut down.");
 script_set_attribute(attribute : "solution" , value : "The latest version confirms that this vulnerability has been fixed, and users are recommended to download and use:http://www.dameng.com/");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:P");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_dependencies("gb_dameng_detect.nasl");
 exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


dameng_port = get_kb_item("dameng_port");
dameng_version = get_kb_item("dameng_version_"+dameng_port);
if( dameng_version =~"^7\.1\." && ver_compare(ver:dameng_version,fix:"7.1.6.33",strict:FALSE)<= 0)
{
	set_kb_item(name:"dameng_version_71633_"+dameng_port,value:dameng_version);
	set_kb_item(name:"dameng_port_71633",value:dameng_port);
	security_hole(port:dameng_port,data:dameng_version);
}
exit();