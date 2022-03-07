###############################################################################
# yangxu ssh get os release
###############################################################################

include("compat.inc");

if (description)
{
  script_id(51799204);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/11/22");

  script_name(english:"Authenticated Check : OS Name and Installed Package Enumeration");
  script_summary(english:"Obtains the remote OS name and installed packages.");

  script_set_attribute(attribute:'synopsis', value:
"This plugin gathers information about the remote host via an
authenticated session.");
 script_set_attribute(attribute:'description', value:
"This plugin logs into the remote host using SSH, RSH, RLOGIN, Telnet,
or local commands and extracts the list of installed packages.

If using SSH, the scan should be configured with a valid SSH public
key and possibly an SSH passphrase (if the SSH public key is protected
by a passphrase).");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Settings");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");

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
nac_ssh = ssh_cmd(cmd:"cat /etc/os-release");
ssh_close_connection();

if ("NAME" >< nac_ssh)
{
  set_kb_item(name:'Host/OS/release', value: nac_ssh);
}
exit(0);
