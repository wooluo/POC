#TRUSTED 0d63ed16eaab16b3cb42da3dbd7071ec1ba5170ae89ab5864500b498868049e63aedcfbcea3305a52a1d7f11e0f44394c1bd083fb7be385dc8893220f2ba573f9e8694be050b837355ea5617fea5209fac140c2fc373d851c1e7bd49d0a3606468fc226ed9f6277e994505edd8094152cbd462445ac4273943b8b814743684f779bea9791c1018a7d7ff3af94f5947a85bd7f2f696bcee29ad5824ebaa1cf929ac0634f5c050c861393a697663d24e7702bd551712816947926019321fb24582fd74539a171a1f97b8055e74c8979307eaf3e2de09d585298454d81c84948ce768a978c8449fbf277aa382f1628412cbf78c3a1bfc0f78c624acd72202ad7f39d2565efed5aec6b62d0d1eaed79a98dd6d161134af2e2b5294270e3bc9db9513afef1ce936bdab1b4200fef26ebf18b4bda801037cbc4c68f4d9051c7d999eb44542c533439ab35a7ae1463419fccdba8fdf35b759189a99ab6c5c6c96729752cab70e5afdb6a63183dd0f9aca96d6d5dbfb1365dc4faebb0411ba83ca92d191b29ef027d7052b777abfdcfb3e55de99388746af8bd56d840d0847a193fab6f08ecb9f773baedb5b75192ea780ebecdc4f020b1874c644a722fe69686db82fcbc9b6cf32576455b9d9e2a586220a4550801166036a2f336db43a33542bcceaea716649501cc14256bf1f917f6ce8347326271ae346f2a70ea2da2f5af5d7fb06
#
# 
#

include("compat.inc");

if (description)
{
  script_id(133723);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

  script_xref(name:"IAVT", value:"0001-T-0559");

  script_name(english:"Cisco Software Maintenance Update Enumeration");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate installed Cisco Software Maintenance Updates on the remote host.");
  script_set_attribute(attribute:"description", value:
"It is possible to enumerate the installed Cisco Software Maintenance Updates on the remote Cisco device using the
command 'show install active'.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_nxos_version.nasl");
  script_require_ports("Host/Cisco/IOS-XR/Version", "Host/Cisco/NX-OS/Version");

 exit(0);
}

include('cisco_kb_cmd_func.inc');

# Lets get the SMU list first
buf = cisco_command_kb_item("Host/Cisco/Config/show_install_active", "show install active");

# Now check if we failed to get the patches
if(!check_cisco_result(buf)) exit(0, "Unable to retrieve patch information.");

# Patches usually have the following pattern:
# disk0:hfr-px-4.3.2.CSCul20020-1.0.0
# disk0:hfr-px-4.3.2.CSCul26557-1.0.0
# disk0:hfr-px-4.3.2.CSCun00853-1.0.0
# disk0:hfr-px-4.3.2.CSCui74251-1.0.0
# But nxos.CSCvr09175-n9k_ALL-1.0.0-<NX-OS_Release>.lib32_n9000 is also seen
pat = "\s*(disk[0-9]+:|flash:|nxos\.)([A-z0-9.\-_]+)";

split = split(buf, keep:true);

patches = '';
report = '';

foreach line (split)
{
  match = pregmatch(pattern:pat, string:line);

  if(isnull(match)) continue;

  if(match[2] >< patches) continue;

  report += '  - ' + match[2] + '\n';
  patches += match[1] + ',';
}

set_kb_item(name:'Host/Cisco/SMU', value:patches);

security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);
