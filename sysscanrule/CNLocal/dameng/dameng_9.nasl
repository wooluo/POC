##达梦数据库存在拒绝服务漏洞


include("compat.inc");
if(description)
{
 script_id(51799167);
 script_category(ACT_GATHER_INFO);
 script_family("CNDB");
 script_name(english:"Dameng DB Denial of service vulnerability");
 script_set_attribute(attribute:"description", value:"There is a denial of service vulnerability in Dameng Database, which can be used by an attacker to cause denial of service (hang or frequent crashes) and affect the availability of data.");
 script_set_attribute(attribute : "solution" , value : "The latest version confirms that this vulnerability has been fixed, and users are recommended to download and use:http://www.dameng.com/");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_dependencies("gb_dameng_detect.nasl");
 exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


dameng_port = get_kb_item("dameng_port");
dameng_version = get_kb_item("dameng_version_"+dameng_port);
if( dameng_version =~"^7\.6\." && ver_compare(ver:dameng_version,fix:"7.6.0.77",strict:FALSE)<= 0)
{
	security_hole(port:dameng_port,data:dameng_version);
}
exit();