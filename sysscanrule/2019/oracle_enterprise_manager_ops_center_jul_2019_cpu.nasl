#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126777);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/19 11:44:33");

  script_cve_id(
    "CVE-2019-3822",
    "CVE-2019-0211",
    "CVE-2019-1559",
    "CVE-2019-2728",
    "CVE-2019-0196",
    "CVE-2019-0197",
    "CVE-2019-0215",
    "CVE-2019-0217",
    "CVE-2019-0220"
  );

  script_name(english:"Oracle Enterprise Manager Ops Center (Jul 2019 CPU)");
  script_summary(english:"Checks for the patch ID.");
  script_set_attribute(attribute:"synopsis", value:
"An enterprise management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Cloud Control installed on
the remote host is affected by multiple vulnerabilities in
Enterprise Manager Base Platform component:

  - An unspecified vulnerability in Networking (cURL) subcomponent
    of Oracle Enterprise Manager Ops Center, which could allow
    an unauthenticated attacker with network access to
    compromise Enterprise Manager Ops Center. (CVE-2019-3822)

  - An unspecified vulnerability in Networking (OpenSSL) subcomponent
    of Oracle Enterprise Manager Ops Center, which could allow
    an unauthenticated attacker with network access to
    compromise Enterprise Manager Ops Center. (CVE-2019-1559)

  - An unspecified vulnerability in Networking (OpenSSL) subcomponent
    of Oracle Enterprise Manager Ops Center, which could allow
    a low privileged attacker with network access to
    compromise Enterprise Manager Ops Center. (CVE-2019-2728)

");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2019
Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3822");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager_ops_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_ops_center_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Ops Center");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('install_func.inc');

get_kb_item_or_exit('Host/local_checks_enabled');
app_name = 'Oracle Enterprise Manager Ops Center';

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
version_full = install['Full Patch Version'];
path = install['path'];
patch_version = install['Patch Version'];


patchid = NULL;
fix = NULL;

if (version_full =~ "^12\.3\.3\.")
{
  patchid = '29943334';
  fix = '1821';
} 

if (isnull(patchid))
  audit(AUDIT_HOST_NOT, 'affected');

if (ver_compare(ver:patch_version, fix:fix, strict:FALSE) != -1)
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version_full, path);

report = 
  '\n Path                : ' + path + 
  '\n Version             : ' + version + 
  '\n Ops Agent Version   : ' + version_full + 
  '\n Current Patch       : ' + patch_version + 
  '\n Fixed Patch Version : ' + fix +
  '\n Fix                 : ' + patchid;

security_report_v4(extra:report, severity:SECURITY_HOLE, port:0);