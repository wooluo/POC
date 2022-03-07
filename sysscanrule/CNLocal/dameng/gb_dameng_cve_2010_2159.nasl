
include("compat.inc");
if(description)
{
 script_id(51799172);
 script_category(ACT_GATHER_INFO);
 script_family("CNDB");
 script_cve_id("CVE-2010-2159");
 script_dependencies("gb_dameng_detect.nasl");
 script_set_attribute(attribute:"description", value:"Dameng DM Database Server allows remote authenticated users to cause a denial of service (crash) and possibly execute arbitrary code via unspecified vectors related to the SP_DEL_BAK_EXPIRED procedure in wdm_dll.dll, which triggers memory corruption.");
 script_set_attribute(attribute : "solution" , value : "The latest version confirms that this vulnerability has been fixed, and users are recommended to download and use:http://www.dameng.com/");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_attribute(attribute:"risk_factor", value:"Medium");
 script_name(english:"DM Database Server 'SP_DEL_BAK_EXPIRED' Memory Corruption Vulnerability");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

dameng_port = get_kb_item("dameng_port");
dameng_version = get_kb_item("dameng_version_"+dameng_port);
if( dameng_version && ver_compare(ver:dameng_version,fix:"7.1",strict:FALSE)<= 0)
{
	security_hole(port:dameng_port,data:dameng_version);
}