##达梦数据库管理系统DBA账号远程缓冲区溢出漏洞

include("compat.inc");

if(description)
{
 script_id(51799169);
 script_category(ACT_GATHER_INFO);
 script_family("CNDB");
 script_name(english:"Dameng DB DBA Account Remote Buffer Overflow Vulnerability");
 script_set_attribute(attribute:"description", value:"The latest version of Dameng database management system 7.1.5.145 has a buffer overflow vulnerability. After an attacker logs in with DBA authority and adds a log, after modifying the path to a deformed string of a certain length after ADD LOGFILE, the service can be down.");
 script_set_attribute(attribute : "solution" , value : "The latest version confirms that this vulnerability has been fixed, and users are recommended to download and use:http://www.dameng.com/");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
 script_set_attribute(attribute:"risk_factor", value:"Low");
 script_dependencies("gb_dameng_detect.nasl");
 exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


dameng_port = get_kb_item("dameng_port");
dameng_version = get_kb_item("dameng_version_"+dameng_port);
if( dameng_version =~"^7\.1\." && ver_compare(ver:dameng_version,fix:"7.1.5.145",strict:FALSE)<= 0)
{
	set_kb_item(name:"dameng_version_715145_"+dameng_port,value:dameng_version);
	set_kb_item(name:"dameng_port_715145",value:dameng_port);
	security_hole(port:dameng_port,data:dameng_version);
}
exit();