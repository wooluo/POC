##达梦数据库存在信息泄露漏洞

include("compat.inc");

if(description)
{
 script_id(51799161);
 script_category(ACT_GATHER_INFO);
 script_family("CNDB");
 script_name(english:"Dameng DB Information Disclosure Vulnerability");
 script_set_attribute(attribute:"description", value:"Dameng database has an information disclosure vulnerability. Low-privileged users can use the vulnerability to view all operations and data in the database.");
 script_set_attribute(attribute : "solution" , value : "The latest version confirms that this vulnerability has been fixed, and users are recommended to download and use:http://www.dameng.com/");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:P");
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