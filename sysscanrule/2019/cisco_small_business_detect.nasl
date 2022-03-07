###
#  (C) WebRAY, Inc.
###

include("compat.inc");

if (description)
{
 script_id(122115);
 script_version("1.1");
 script_cvs_date("Date: 2019/02/12 11:35:31");

 script_name(english:"Cisco Small Business Router SNMP Detection");
 script_summary(english:"Detect Cisco Small Business Router via SNMP");

 script_set_attribute(attribute:"synopsis", value:
"GizaNE detected a remote router");
 script_set_attribute(attribute:"description", value:
"Using SNMP, GizaNE has determined that the remote host is a Cisco Small Business Router");
 # https://www.cisco.com/c/en/us/solutions/small-business/routers.html
 script_set_attribute(attribute:"see_also", value:"");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv320_dual_gigabit_wan_vpn_router");
 script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv325_dual_gigabit_wan_vpn_router");
 script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:small_business_router");

 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CISCO");

 script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

 script_dependencies("os_fingerprint_snmp.nasl");
 script_require_keys("Host/OS/SNMP");
 script_require_ports("Services/udp", 161);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

device = NULL;
version = NULL;

os = get_kb_item_or_exit("Host/OS/SNMP");
if ("Cisco Small Business" >!< os)
  audit(AUDIT_HOST_NOT, "Cisco Small Business Router");

version = pregmatch(pattern:"\s([0-9]+\.[0-9.]+)$", string:os);
if (!isnull(version) && !isnull(version[1]))
  version = version[1];
else
  version = "unknown";
set_kb_item(name:"Cisco/Small_Business_Router/Version", value:version);


device = get_kb_item("Host/OS/SNMP/Device");
if (isnull(device))
  device = "unknown";
set_kb_item(name:"Cisco/Small_Business_Router/Device", value:device);

report = '\n  Device           : ' + device +
         '\n  Software version : ' + version +
         '\n';

security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);

exit(0);



