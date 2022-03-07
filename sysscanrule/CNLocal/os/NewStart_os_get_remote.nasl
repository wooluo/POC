###############################################################################
# yangxu 检测到目标主机运行着中兴新支点电信级服务器操作系统 61.134.56.5 
###############################################################################


if(description)
{
  script_id(51799214);
  script_version("$Revision: 13 $");
  script_name(english:"Check NewStart OS");
  script_summary(english:"Check NewStart working");
  script_copyright(english:"This script is Copyright (C) 2017 WebRAY, Inc.");
  script_category(ACT_GATHER_INFO);
  script_set_attribute(attribute:"risk_factor", value:"Low");
  script_family("CNLocal");
  script_dependencies("telnet_clear_text.nasl");
  script_require_ports("Services/telnet", 23);
  exit(0);
}


include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");
include("telnet2_func.inc");

cmdline = 0;
port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);
if (!get_port_state(port)) exit(0);
issue = get_kb_item("Services/telnet/banner/" + port);
if ("NewStart CGS Linux" >< issue && "Released By ZTE)" >< issue)
{
	security_hole(port:port,data:issue);
}
exit(0);
