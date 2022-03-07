#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122483);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/30 14:30:16");

  script_cve_id("CVE-2019-1663");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn18638");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn18639");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn18642");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190227-rmi-cmd-ex");

  script_name(english:"Cisco RV110W, RV130W, and RV215W Routers Management Interface Remote Command Execution Vulnerability (cisco-sa-20190227-rmi-cmd-ex)");
  script_summary(english:"Checks router version");

  script_set_attribute(attribute:"synopsis",value:
"The remote host is affected by a remote command execution vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of the Cisco
Small Business Wireless-N VPN Router installed on the remote host is
affected by a remote command execution vulnerability. An
unauthenticated, remote attacker can exploit this to bypass 
authentication and execute arbitrary commands as a high-privilege
user.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190227-rmi-cmd-ex
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security
Advisory cisco-sa-20190227-rmi-cmd-ex.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1663");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco RV130W Routers Management Interface Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv110w_wireless-n_vpn_firewall");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv130w_wireless-n_multifunction_vpn_router");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv215w_wireless-n_vpn_router");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Device");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

device = get_kb_item_or_exit("Cisco/Small_Business_Router/Device");
version = get_kb_item_or_exit("Cisco/Small_Business_Router/Version");

if (device =~ "^RV110W")
{
  fix = "1.2.2.1";
  bug = "CSCvn18639";
}
else if (device =~ "^RV130W")
{
  fix = "1.0.3.45";
  bug = "CSCvn18638";
}
else if (device =~ "^RV215W")
{
  fix = "1.3.1.1";
  bug = "CSCvn18642";
}
else
  audit(AUDIT_HOST_NOT, "an RV110W, RV130W, or RV215W router");

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0 )
{
  report =
    '\n  Bug               : ' + bug +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix;
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco " + device + " router", version);
