#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121247);
  script_version("1.4");
  script_cvs_date("Date: 2019/04/18 12:05:36");

  script_cve_id(
    "CVE-2018-0734",
    "CVE-2018-0735",
    "CVE-2018-3309",
    "CVE-2018-5407",
    "CVE-2019-2446",
    "CVE-2019-2448",
    "CVE-2019-2500",
    "CVE-2019-2501",
    "CVE-2019-2504",
    "CVE-2019-2505",
    "CVE-2019-2506",
    "CVE-2019-2508",
    "CVE-2019-2509",
    "CVE-2019-2511",
    "CVE-2019-2520",
    "CVE-2019-2521",
    "CVE-2019-2522",
    "CVE-2019-2523",
    "CVE-2019-2524",
    "CVE-2019-2525",
    "CVE-2019-2526",
    "CVE-2019-2527",
    "CVE-2019-2548",
    "CVE-2019-2550",
    "CVE-2019-2551",
    "CVE-2019-2552",
    "CVE-2019-2553",
    "CVE-2019-2554",
    "CVE-2019-2555",
    "CVE-2019-2556"
  );
  script_bugtraq_id(
    105750,
    105758,
    105897,
    106568,
    106572,
    106574,
    106613
  );

  script_name(english:"Oracle VM VirtualBox 5.2.x < 5.2.24 / 6.0.x < 6.0.2 (Jan 2019 CPU)");
  script_summary(english:"Performs a version check on VirtualBox");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The version of Oracle VM VirtualBox running on the remote host is
5.2.x prior to 5.2.24 or 6.0.x prior to 6.0.2. It is, therefore,
affected by multiple vulnerabilities as noted in the January 2018
Critical Patch Update advisory :

  - A denial of service vulnerability in the bundled
    third-party component OpenSSL library's DSA signature
    algorithm that renders it vulnerable to a timing side
    channel attack. An attacker could leverage this
    vulnerability to recover the private key.
    (CVE-2018-0734)

  - Multiple unspecified vulnerabilities in the Core
    component of Oracle VirtualBox could allow an
    authenticated, local attacker with logon to the
    infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. (CVE-2018-3309,
    CVE-2019-2500, CVE-2019-2520, CVE-2019-2521,
    CVE-2019-2522, CVE-2019-2523, CVE-2019-2524,
    CVE-2019-2526, CVE-2019-2548, CVE-2019-2552)

  - Multiple unspecified vulnerabilities in the Core
    component of Oracle VirtualBox could allow an
    authenticated, local attacker with logon to the
    infrastructure where Oracle VM VirtualBox executes to
    potentially expose critical or confidential data.
    (CVE-2019-2446, CVE-2019-2448, CVE-2019-2450,
    CVE-2019-2451, CVE-2019-2501, CVE-2019-2504,
    CVE-2019-2505, CVE-2019-2506, CVE-2019-2525,
    CVE-2019-2553, CVE-2019-2554, CVE-2019-2555,
    CVE-2019-2556)

  - Multiple denial of service vulnerabilities in the Core
    component of Oracle VirtualBox could allow an
    authenticated, local attacker with logon to the
    infrastructure where Oracle VM VirtualBox executes to
    cause a denial of service condition. (CVE-2019-2508,
    CVE-2019-2509, CVE-2019-2527)

  - An denial of service vulnerabilities with the SOAP
    protocol in the Core component of Oracle VirtualBox
    could allow an unauthenticated, remote attacker, to
    potentially a denial of service condition.
    (CVE-2019-2511)

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html#AppendixOVIR
  script_set_attribute(attribute:"see_also",value:"");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 5.2.24, 6.0.2 or later as
referenced in the January 2019 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2511");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
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
  {"min_version" : "5.2", "fixed_version" : "5.2.24"},
  {"min_version" : "6.0", "fixed_version" : "6.0.2"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
