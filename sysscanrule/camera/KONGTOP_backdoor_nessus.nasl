###############################################################################
# Nessus Vulnerability Test
#
###############################################################################
include("compat.inc");

if (description)
{
  script_id(51799084);
  script_version("1.25");

  script_name(english:"KONGTOP telnet");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_summary(english:"KONGTOP have a telnet backdoor, which will directly return the login password.");
  script_set_attribute(attribute:"description", value:"KONGTOP DVR devices A303, A403, D303, D305 and D403 have a telnet backdoor, which will directly return the login password");
  script_set_attribute(attribute:"solution", value:"Encrypt and store sensitive files to prevent leakage of sensitive information.");
 

  script_copyright(english:"This script is Copyright (C) 2001-2018 WEBRAY");
  script_family(english:"Camera");

  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports(23);

   exit(0);
}

include("audit.inc");
include("global_settings.inc");
include('telnet_func.inc');

port = 23; # the port can't be changed

banner = get_telnet_banner(port:port);
#display(banner);
if ( "passwd" >< banner ){
if (report_verbosity > 0) security_hole(port:port, extra:banner);
			  else security_hole(port);
}
