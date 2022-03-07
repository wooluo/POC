##达梦数据库服务器存在越权访问漏洞

include("compat.inc");

if(description)
{
 script_id(51799160);
 script_category(ACT_GATHER_INFO);
 script_family("CNDB");
 script_name(english:"Dameng DB Unauthorized access vulnerability");
 script_set_attribute(attribute:"description", value:"The Dameng database server has an unauthorized access vulnerability. An attacker can use the vulnerability to illegally obtain the DBA role and then control the entire database.");
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
if( dameng_version =~"^7\.1\." && ver_compare(ver:dameng_version,fix:"7.1.6.3",strict:FALSE)<= 0)
{
	set_kb_item(name:"dameng_version_7163_"+dameng_port,value:dameng_version);
	set_kb_item(name:"dameng_port_7163",value:dameng_port);
	security_hole(port:dameng_port,data:dameng_version);
}
exit();