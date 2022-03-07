##达梦数据库存在同义词（函数）提权漏洞

include("compat.inc");

if(description)
{
 script_id(51799164);
 script_category(ACT_GATHER_INFO);
 script_family("CNDB");
 script_name(english:"Dameng DB Synonym (function) elevation of privilege vulnerability");
 script_set_attribute(attribute:"description", value:"The DM7 database has a synonym (function) elevation privilege vulnerability. Low-privilege users can control the entire database by creating public synonym privileges to achieve dba elevation.");
 script_set_attribute(attribute : "solution" , value : "The latest version confirms that this vulnerability has been fixed, and users are recommended to download and use:http://www.dameng.com/");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_dependencies("dameng_4.nasl");
 exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

dameng_port = get_kb_item("dameng_port_71633");
dameng_version = get_kb_item("dameng_version_71633_"+dameng_port);
if( dameng_version && dameng_port)
{
	security_hole(port:dameng_port,data:dameng_version);
}
exit();