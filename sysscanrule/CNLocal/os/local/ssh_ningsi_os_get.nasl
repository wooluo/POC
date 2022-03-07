###############################################################################
# yangxu 检测到目标主机运行着红旗操作系统
###############################################################################


if(description)
{
  script_id(51799183);
  script_version("$Revision: 13 $");
  script_name("Check linx OS (local check)");
  script_summary("Check linx working");
  script_copyright(english:"This script is Copyright (C) 2017 WebRAY, Inc.");
  script_category(ACT_ATTACK);
  script_set_attribute(attribute:"risk_factor", value:"Low");
  script_family("CNLocal");
  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22);
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("ssh_get_info2.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");
include("data_protection.inc");

cmdline = 0;



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS)
  enable_ssh_wrappers();
else disable_ssh_wrappers();

# 1. SSH
# setup ssh tunnel
uname = get_kb_item_or_exit("Host/uname");
if ( "Linux" >!< uname ) exit(1, "The remote OS is not Linux-based");

sock_g = ssh_open_connection();
if (! sock_g) exit(1, "ssh_open_connection() failed.");
# os-release
nac_ssh = ssh_cmd(cmd:"lsb_release -a");
ssh_close_connection();

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

issue = get_kb_item("Host/etc/issue");


if ("Linx" >< issue)
{
	security_hole(port:port,data:issue);
}

if ("Linx" >< nac_ssh)
{
	security_hole(port:port,data:nac_ssh);
}
exit(0);