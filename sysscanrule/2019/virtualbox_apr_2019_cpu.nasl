#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124167);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/30 14:30:16");

  script_cve_id(
    "CVE-2019-2656",
    "CVE-2019-2680",
    "CVE-2019-2696",
    "CVE-2019-2703",
    "CVE-2019-2721",
    "CVE-2019-2722",
    "CVE-2019-2723",
    "CVE-2019-2657",
    "CVE-2019-2690",
    "CVE-2019-2679",
    "CVE-2019-2678",
    "CVE-2019-2574"
  );
  script_bugtraq_id(107960);
  script_xref(name:"IAVA", value:"2019-A-0120");

  script_name(english:"Oracle VM VirtualBox 5.2.x < 5.2.28 / 6.0.x < 6.0.6 (Apr 2019 CPU)");
  script_summary(english:"Performs a version check on VirtualBox");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The version of Oracle VM VirtualBox running on the remote host is
5.2.x prior to 5.2.28 or 6.0.x prior to 6.0.6. It is, therefore,
affected by multiple vulnerabilities as noted in the April 2019
Critical Patch Update advisory :

  - Multiple unspecified vulnerabilities in the Core
    component of Oracle VirtualBox could allow an
    authenticated, local attacker with logon to the
    infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. 
    (CVE-2019-2656, CVE-2019-2657,CVE-2019-2680,CVE-2019-2690,
     CVE-2019-2696,CVE-2019-2703,CVE-2019-2721,CVE-2019-2722,
     CVE-2019-2723)

  - Multiple unspecified vulnerabilities in the Core
    component of Oracle VirtualBox could allow an
    authenticated, local attacker with logon to the
    infrastructure where Oracle VM VirtualBox executes to
    potentially expose critical or confidential data.
    (CVE-2019-2574, CVE-2019-2678, CVE-2019-2679) ");

  #https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html#AppendixOVIR
  script_set_attribute(attribute:"see_also",value:"");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 5.2.28, 6.0.6 or later as
referenced in the April 2019 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2656");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/18");

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

include("vcf.inc");

if (get_kb_item("installed_sw/Oracle VM VirtualBox"))
  app_info = vcf::get_app_info(app:"Oracle VM VirtualBox", win_local:TRUE);
else
  app_info = vcf::get_app_info(app:"VirtualBox");

constraints = [
  {"min_version" : "5.2", "fixed_version" : "5.2.28"},
  {"min_version" : "6.0", "fixed_version" : "6.0.6"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
