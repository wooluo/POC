##达梦数据库管理系统存在提权漏洞


include("compat.inc");
if(description)
{
 script_id(51799168);
 script_category(ACT_GATHER_INFO);
 script_family("CNDB");
 script_name(english:"Dameng DB Elevation of Privilege Vulnerability");
 script_set_attribute(attribute:"description", value:"Dameng database management system has a privilege escalation vulnerability, which can be used by attackers to gain server permissions.");
 script_set_attribute(attribute : "solution" , value : "The latest version confirms that this vulnerability has been fixed, and users are recommended to download and use:http://www.dameng.com/");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
 script_set_attribute(attribute:"risk_factor", value:"Medium");
 script_dependencies("gb_dameng_detect.nasl");
 exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

dameng_port = get_kb_item("dameng_port");
dameng_version = get_kb_item("dameng_version_"+dameng_port);
if( dameng_version =~"^8\.1\." && ver_compare(ver:dameng_version,fix:"8.1.0.147",strict:FALSE)<= 0)
{
	security_hole(port:dameng_port,data:dameng_version);
}
exit();