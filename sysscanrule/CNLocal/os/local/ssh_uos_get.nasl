###############################################################################
# yangxu 检测到目标主机运行着统信UOS操作系统
###############################################################################


if(description)
{
  script_id(51799311);
  script_version("$Revision: 13 $");
  script_name(english:"Check UOS (local check)");
  script_summary(english:"Check UOS working");
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

issue = get_kb_item("Host/etc/issue");

release = get_kb_item("Host/OS/release");

if ("Uniontech OS Server" >< issue)
{
	security_hole(port:port,data:issue);
}
if ("Uniontech OS Server" >< release || 'HOME_URL="https://www.chinauos.com/"' >< release)
{
	security_hole(port:port,data:release);
}

exit(0);
