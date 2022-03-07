###############################################################################
# yangxu 检测到目标主机运行着EulerOS操作系统
###############################################################################


if(description)
{
  script_id(51799180);
  script_version("$Revision: 13 $");
  script_name(english:"Check EulerOS OS (local check)");
  script_summary(english:"Check EulerOS working on remote");
  script_copyright(english:"This script is Copyright (C) 2017 WebRAY, Inc.");
  script_category(ACT_ATTACK);
  script_set_attribute(attribute:"risk_factor", value:"Low");
  script_family("CNLocal");
  script_dependencies("ssh_get_os_release_info.nasl");
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

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

issue = get_kb_item("Host/OS/release");

if ("EulerOS" >< issue)
{
	security_hole(port:port,data:issue);
}
exit(0);
