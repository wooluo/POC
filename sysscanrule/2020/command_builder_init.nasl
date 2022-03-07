#TRUSTED 9f152e5805c06db118f0aaa8d948fdab089ab28b4a3aa15125353ecb448bd89256602c0bd76dcda24bdbad046a8d7bd413501a72439204a9a4f19fb1a00452f2851f7698de47f7c28bcc14363fa2aa815b96d645b27a9437e3ade6361cf304a7fd4f3e4c2920bccfc089b50587b34cdd3cdb001b137c17e1e6ad24182c6b3540406b5a3b7519d36f999cf4e4a776b353f36755ba2a8befd0353c670bdb86f0866c41182efdd83b4932d7404e039df5c2b2177ac36b777099fc7ccca613b4a44a1d3c39f948bd11d6f5e6c5376cec7904167df97a019415d606c305510b64c508ebd4966ac9e1b88a2ac38522ce33548814359200ad842960dbd92041f6080e907f87369d0c82c62f16d4cfce0b715476588821ba5483407325286bb805613e28fc10d5db709727c39e99f07c0009a5e04db46c6fef5bde6542f92c7867ef5110bade1056e89f2163151c748a1e930017ee1cf4d713db78420198ce6dac841023211ed2e30a10d13d51168dd008ca66360da8c8090ca7763c0bce78b6968a9ff89a3498730ff90a02e98a42fa013242206507b1f358265452f1cd8ed854538ccc12e285449bd6945a79a9b9ea318009c4d0fcd21aba8b7e6a81b780f7571c8ab39b3af1864018cf147824d4394c026482a2969f7ce9bed09fe20e809c4b6a36c35588ed0a387fcfa14f941b9efa1f132318a32dceafd498fb9f1b11aff1ef37e3

#
# 
#

include("compat.inc");

if (description)
{
  script_id(131286);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/11/25");

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

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    get_kb_item("Host/HP-UX/version"))
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


