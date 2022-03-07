##达梦数据库服务器存在拒绝服务漏洞

include("compat.inc");

if(description)
{
 script_id(51799163);
 script_category(ACT_GATHER_INFO);
 script_family("CNDB");
 script_name(english:"Dameng DB Denial of service vulnerability");
 script_set_attribute(attribute:"description", value:"A buffer overflow vulnerability exists in the authentication function of the Dameng Database. Will cause database downtime and even control the operating system.");
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
if( dameng_version =~"^7\.1\.3\." && (ver_compare(ver:dameng_version,fix:"7.1.3.53",strict:FALSE) == 0 || ver_compare(ver:dameng_version,fix:"7.1.3.55",strict:FALSE) == 0))
{
	security_hole(port:dameng_port,data:dameng_version);
}
exit();