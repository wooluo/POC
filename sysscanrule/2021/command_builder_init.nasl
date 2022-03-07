#TRUSTED 61bf19138f28e38e3f687c9a49fb2fb1243a4700d9576d58a10f8ba2935fe7556ff2d6aece1327956800948fc1ffcf0d82ee102174bc1233d0920dc2be8487bb28b1d0b413e0c916efc92cadfc4c4466cfd44d6fc0e841de58dba9485ae4e2f3bdf6db54bedb8d43980453389fde927a8ad15209bd219b79f316b7ab7704cac965811cedb42815cf6a6bf75a37484fd1d6a628a1894e5f8a62237393b826b9e1fb3dea73b9648135c2ce69185cb628ac9678987b88c0dcfe5a4f3041d30a94610975ef03ff08249962964b6b311af72e0402151d2533371f0f2626d3a487b0cc26c2032689dacfbdf61c5161c302ed6b18f96440c9279587fd4938909677693886bdd1bcaba459a304c52b928a81b31d36ae76fd16ee26d6908cd207138e832dce9c6fd67da3b8a336129825053e7df7cd424da9a9bd7f987236a69437dbbcf1350e6499cad5b6058601ca5ff047e7204fa094f6f7fa750795a776aa0b8526f0c7229f6498439c15a1268fff49eb4762061c7713c81fb227bcfec15810e96cac29f441eee1d287d382acf26e0957e951d16aebe4d3125b3d1e6a6090247f85fca9ba7e57b1d7a050bdcfa9e34673327b38afbfd218cc6cd001cdb0b4039d7efb8410a738328eeb0312a9c9df152c76359bd7f1fd13e55b2af51e9e02978d308f0045d939304126afdd24e316d08920716ba4eeed651dd86a22b23f39ffe6ce50

#
# 
#

include("compat.inc");

if (description)
{
  script_id(131286);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/28");

  script_name(english:"Command Builder Initialization");
  script_summary(english:"Initialize command builder library.");

  script_set_attribute(attribute:"synopsis", value:
"Query host to initialize command builder functionality.");
  script_set_attribute(attribute:"description", value:
"Query host for the existance and functionality of commands wrapped by the command builder library.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");
include("command_builder.inc");
include("sh_commands_find.inc");
include("spad_log_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

uname = get_kb_item("Host/uname");

if (isnull(uname)) uname = '';

if ("Linux" >< uname ||
    "Darwin" >< uname ||
    get_kb_item("Host/Solaris/Version") ||
    get_kb_item("Host/Solaris11/Version") ||
    get_kb_item("Host/AIX/version") ||
    get_kb_item("Host/HP-UX/version") ||
    get_kb_item("Host/FreeBSD/release") )
{
  if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS)
  {
    enable_ssh_wrappers();
  }
  else
  {
    disable_ssh_wrappers();
  }

  if (islocalhost())
  {
    if (!defined_func("pread") )
    {
      spad_log_and_exit(exit_level:1, exit_msg:"'pread()' is not defined.");
    }
    info_t = INFO_LOCAL;
  }
  else
  {
    sock_g = ssh_open_connection();
    if (!sock_g)
    {
      spad_log_and_exit(exit_level:1, exit_msg:"Failed to open an SSH connection.");
    }

    info_t = INFO_SSH;
  }

  command_builder::init_cmd_runner();
  sh_commands_find::init_find();

  if(info_t == INFO_SSH) ssh_close_connection();

  exit(0);
}
else
{
  exit(0, "Unsupported operating system.");
}


