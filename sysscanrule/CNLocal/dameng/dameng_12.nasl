##达梦数据库管理系统缓冲区溢出漏洞

include("compat.inc");

if(description)
{
 script_id(51799170);
 script_category(ACT_GATHER_INFO);
 script_family("CNDB");
 script_name(english:"Dameng DB Buffer Overflow Vulnerability");
 script_set_attribute(attribute:"description", value:"The latest version of Dameng database management system 7.1.5.145 has a buffer overflow vulnerability. After an attacker logs in with DBA authority and expands the log, when the path is modified to a deformed string of a certain length after RESIZE LOGFILE, the service can be down.");
 script_set_attribute(attribute : "solution" , value : "The latest version confirms that this vulnerability has been fixed, and users are recommended to download and use:http://www.dameng.com/");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
 script_set_attribute(attribute:"risk_factor", value:"Low");
 script_dependencies("dameng_11.nasl");
 exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

dameng_port = get_kb_item("dameng_port_715145");
dameng_version = get_kb_item("dameng_version_715145_"+dameng_port);
if( dameng_version && dameng_port)
{
	security_hole(port:dameng_port,data:dameng_version);
}
exit();