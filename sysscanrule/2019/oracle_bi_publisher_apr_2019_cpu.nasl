#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124121);
  script_version("1.4");
  script_cvs_date("Date: 2019/04/30 14:30:16");

  script_cve_id(
    "CVE-2019-2588",
    "CVE-2019-2595",
    "CVE-2019-2601",
    "CVE-2019-2616"
  );
  script_xref(name:"IAVA", value:"2019-A-0128");

  script_name(english:"Oracle Business Intelligence Publisher Multiple Vulnerabilities (Apr 2019 CPU)");
  script_summary(english:"Checks for applied patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Publisher running on the
remote host is 11.1.1.9.x prior to 11.1.1.9.190416, 12.2.1.3.x prior
to 12.2.1.3.190416, or 12.2.1.4.x prior to 12.2.1.4.190416. It is,
therefore, affected by  multiple vulnerabilities as noted in the
April 2019 Critical 
Patch Update advisory:

  - An unspecified vulnerability in the BI Publisher Security
    component of Oracle BI Publisher (formerly XML Publisher) that
    could allow a privileged attacker with network access
    via HTTP to compromise Oracle BI Publisher . A successful
    attack of this vulnerability could result in unauthorized
    access to critical data or complete access to all Oracle BI
    Publisher accessible data. (CVE-2019-2588)

  - An unspecified vulnerability in the BI Publisher Security
    component of Oracle BI Publisher (formerly XML Publisher) that
    could allow an unauthenticated attacker with network access
    via HTTP to compromise Oracle BI Publisher . A successful
    attack of this vulnerability could result in unauthorized
    access to critical data or complete access to all Oracle BI
    Publisher accessible data. The attack requires human
    interaction. (CVE-2019-2595, CVE-2019-2616)

  - An unspecified vulnerability in the BI Publisher Security
    component of Oracle BI Publisher (formerly XML Publisher) that
    could allow a low privileged attacker with network access
    via HTTP to compromise Oracle BI Publisher . A successful
    attack of this vulnerability could result in unauthorized
    access to critical data or complete access to all Oracle BI
    Publisher accessible data. The attack requires human
    interaction. (CVE-2019-2601)

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2019 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2616");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bi_publisher_installed.nbin", "oracle_bi_publisher_detect.nasl");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
appname = 'Oracle Business Intelligence Publisher';
app_info = vcf::get_app_info(app:appname);

# 11.1.1.9.x - Bundle: 29492717 | Patch: 29444334
# 12.2.1.3.x - Bundle: 29112070 | Patch: 29112070
# 12.2.1.4.x - Bundle: 28952857 | Patch: 28952857
constraints = [
  {'min_version': '11.1.1.9', 'fixed_version': '11.1.1.9.190416', 'patch': '29444334', 'bundle': '29492717'},
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.190416', 'patch': '29112070', 'bundle': '29112070'},
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.190416', 'patch': '28952857', 'bundle': '28952857'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_WARNING);
