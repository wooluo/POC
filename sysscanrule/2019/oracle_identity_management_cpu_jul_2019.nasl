#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126827);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/19 16:15:47");

  script_cve_id("CVE-2019-2858");
  script_bugtraq_id(109252);

  script_name(english:"Oracle Identity Manager Remote Security Vulnerability (Jul 2019 CPU)");
  script_summary(english:"Checks for the July 2019 CPU.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a remote
security vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing the July 2019 Critical Patch Update for
Oracle Identity Manager. It is, therefore, affected by an unspecified
vulnerability in the Advanced Console of Oracle Identity Manager, which
could allow an authenticated, remote attacker via HTTP to compromise
Oracle Identity Manager which can result in unauthorized update, insert
or delete access to some of Oracle Identity Manager accessible data as
described in the July 2019 critical patch update advisory.

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2019 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2858");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:identity_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_identity_management_installed.nbin");
  script_require_keys("installed_sw/Oracle Identity Manager");

  exit(0);
}
include('vcf.inc');

appname = 'Oracle Identity Manager';

app_info = vcf::get_app_info(app:appname);
 
constraints = [
  {'min_version': '11.1.2.2', 'fixed_version': '11.1.2.3.190328'},
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.190624'}
];
vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_WARNING);