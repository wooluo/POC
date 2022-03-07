##达梦数据库存在提权漏洞

include("compat.inc");
if(description)
{
 script_id(51799159);
 script_category(ACT_GATHER_INFO);
 script_family("CNDB");
 script_name(english:"Dameng DB Elevation of Privilege Vulnerability");
 script_set_attribute(attribute:"description", value:"There is a vulnerability escalation in Dameng database. Due to insufficient permissions of certain functions and restrictions on parameters, an attacker can directly control the operating system where Dameng database is located through a set of operations.");
 script_set_attribute(attribute : "solution" , value : "The latest version confirms that this vulnerability has been fixed, and users are recommended to download and use:http://www.dameng.com/");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:P");
 script_set_attribute(attribute:"risk_factor", value:"Medium");
 script_dependencies("dameng_158_1.nasl");
 exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

dameng_port = get_kb_item("dameng_port_158");
dameng_version = get_kb_item("dameng_version_158_"+dameng_port);
if( dameng_version =~"^7\.1\." && (ver_compare(ver:dameng_version,fix:"7.1.5.158",strict:FALSE)<= 0))
{
	security_hole(port:dameng_port,data:dameng_version);
}
exit();