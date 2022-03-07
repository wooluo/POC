#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126778);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/18 15:47:53");

  script_cve_id(
    "CVE-2019-2859",
    "CVE-2019-2867",
    "CVE-2019-2866",
    "CVE-2019-2864",
    "CVE-2019-2865",
    "CVE-2019-1543",
    "CVE-2019-2863",
    "CVE-2019-2848",
    "CVE-2019-2877",
    "CVE-2019-2873",
    "CVE-2019-2874",
    "CVE-2019-2875",
    "CVE-2019-2876",
    "CVE-2019-2850"
  );
  script_bugtraq_id(
    107349,
    109190,
    109194,
    109198,
    109200,
    109204,
    109208
  );
  script_xref(name:"IAVA", value:"2019-A-0253");

  script_name(english:"Oracle VM VirtualBox 5.2.x < 5.2.32 / 6.0.x < 6.0.10 (Jul 2019 CPU)");
  script_summary(english:"Performs a version check on VirtualBox");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The version of Oracle VM VirtualBox running on the remote host is 5.2.x prior to 5.2.32 or 6.0.x prior to 6.0.10. 
It is, therefore, affected by multiple vulnerabilities as noted in the July 2019 Critical Patch Update advisory:

  - An unspecified vulnerabilities in the Oracle VM VirtualBox component of Oracle Virtualization (subcomponent: Core), 
    which could allow an authenticated, local attacker to takeover Oracle VM VirtualBox. (CVE-2019-2859, CVE-2019-2863, 
    CVE-2019-2866, CVE-2019-2867) 

  - An unspecified vulnerability in the Oracle VM VirtualBox component of Oracle Virtualization (subcomponent: Core
    (OpenSSL)), which could allow an unauthenticated, remote attacker to create, delete of modify critical data Oracle
    VM VirtualBox. (CVE-2019-1543)

  - An unspecified vulnerabilities in the Oracle VM VirtualBox component of Oracle Virtualization (subcomponent: Core), 
    which could allow an authenticated, local attacker to cause a hang or repeatable crach (DoS) of Oracle VM
    VirtualBox. (CVE-2019-2848, CVE-2019-2873, CVE-2019-2874, CVE-2019-2875, CVE-2019-2876, CVE-2019-2877) ");

  # https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html#AppendixOVIR
  script_set_attribute(attribute:"see_also",value:"");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 5.2.32, 6.0.10 or later as referenced in the July 2019 Oracle Critical 
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2859");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("virtualbox_installed.nasl", "macosx_virtualbox_installed.nbin");
  script_require_ports("installed_sw/Oracle VM VirtualBox", "installed_sw/VirtualBox");

  exit(0);
}

include('vcf.inc');

if (get_kb_item('installed_sw/Oracle VM VirtualBox'))
  app_info = vcf::get_app_info(app:'Oracle VM VirtualBox', win_local:TRUE);
else
  app_info = vcf::get_app_info(app:'VirtualBox');

constraints = [
  {'min_version' : '5.2', 'fixed_version' : '5.2.32'},
  {'min_version' : '6.0', 'fixed_version' : '6.0.10'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
