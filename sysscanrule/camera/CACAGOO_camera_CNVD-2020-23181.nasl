include("compat.inc");


if (description)
{
  script_id(51799272);
  script_cve_id("CVE-2020-6852");
  script_version("1.3");
  script_name(english:"CACAGOO camera  CVE-2020-6852");
  script_summary(english:"CACAGOO camera CVE-2020-6852");
  script_set_attribute(attribute:"description", value:"CACAGOO Cloud Storage Intelligent Camera TV-288ZD-2MP with firmware 3.4.2.0919 has weak authentication of TELNET access, leading to root privileges without any password required.");
  script_set_attribute(attribute:"solution", value:"None");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Camera");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  
  script_dependencies("find_service1.nasl", "account_check.nasl");
  script_require_ports("Services/telnet", 23);
  exit(0);
}


############################################
include("audit.inc");
include("default_account.inc");
include('global_settings.inc');

port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);

banner = get_telnet_banner(port:port);
if ('localhost' >!< banner) audit(AUDIT_NOT_LISTEN, 'CACAGOO', port);
r = _check_telnet(port:port, login:'root', password:'cxlinux', cmd:'id', cmd_regex:'uid=[0-9]+.*gid=[0-9]+.*', out_regex_group:1);
if (r)
{
  security_hole(port:port, extra:default_account_report(cmd:"id"));
}

exit(0);
