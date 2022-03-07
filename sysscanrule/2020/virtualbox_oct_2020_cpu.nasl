##
# 
##

include('compat.inc');

if (description)
{
  script_id(141784);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/27");

  script_cve_id(
    "CVE-2020-14872",
    "CVE-2020-14881",
    "CVE-2020-14884",
    "CVE-2020-14885",
    "CVE-2020-14886",
    "CVE-2020-14889",
    "CVE-2020-14892"
  );
  script_xref(name:"IAVA", value:"2020-A-0474");

  script_name(english:"Oracle VM VirtualBox (Oct 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle VM VirtualBox installed on the remote host is affected by multiple vulnerabilities as referenced
 in the October 2020 CPU advisory, including the following:

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported 
    versions that is affected are Prior to 6.1.16. Easily exploitable vulnerability allows high privileged 
    attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM 
    VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact 
    additional products. Successful attacks of this vulnerability can result in takeover of Oracle VM 
    VirtualBox. (CVE-2020-14872)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported 
    versions that is affected are Prior to 6.1.16. Easily exploitable vulnerability allows high privileged 
    attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM 
    VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact 
    additional products. uccessful attacks of this vulnerability can result in unauthorized access to 
    critical data or complete access to all Oracle VM VirtualBox accessible data. 
    (CVE-2020-14881, CVE-2020-14884, CVE-2020-14885, CVE-2020-14886, CVE-2020-14889)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported 
    versions that is affected are Prior to 6.1.16. Easily exploitable vulnerability allows low privileged 
    attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM 
    VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact 
    additional products. Successful attacks of this vulnerability can result in unauthorized ability to cause
    a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox. (CVE-2020-14892)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14872");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("virtualbox_installed.nasl", "macosx_virtualbox_installed.nbin");
  script_require_ports("installed_sw/Oracle VM VirtualBox", "installed_sw/VirtualBox");

  exit(0);
}


include('vcf.inc');

if (get_kb_item('installed_sw/Oracle VM VirtualBox'))
  app_info = vcf::get_app_info(app:'Oracle VM VirtualBox', win_local:TRUE);
else
  app_info = vcf::get_app_info(app:'VirtualBox');

constraints = [{'fixed_version' : '6.1.16'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
