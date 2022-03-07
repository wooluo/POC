#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125547);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/29 12:26:56");

  script_cve_id("CVE-2019-2435");
  script_bugtraq_id(106616);

  script_name(english:"Oracle MySQL Connectors Unspecified Vulnerability (Jan 2019 CPU)");
  script_summary(english:"Checks installed patch/version info.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle MySQL Connectors installed on the remote host is 2.x <= 2.1.8 or 8.x <= 8.1.13.
It is, therefore, affected by unspecified vulnerability in Connector/Python subcomponent. The vulnerability allows
unauthenticated attacker with network access via TLS to compromise MySQL Connectors. Successful attacks can lead to
unauthorized access to critical data.

Note that GizaNE has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches according to the January 2019 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2435");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:connector");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_connectors_version_nix.nbin", "mysql_connectors_version_win.nbin");
  script_require_keys("installed_sw/MySQL Connector");

  exit(0);
}

include('vcf.inc');

#
# Main
#

appname = 'MySQL Connector';

app_info = vcf::get_app_info(app:appname);

vcf::check_granularity(app_info:app_info, sig_segments:3);

if ('python' >< tolower(app_info.Product))
  constraints = [
    {'min_version': '2.0.0', 'max_version' : '2.1.8', 'fixed_display' : '8.0.14'},
    {'min_version': '8.0.0', 'fixed_version': '8.0.14'}
  ];
else
  audit(AUDIT_PACKAGE_NOT_AFFECTED, app_info.Product);

vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_WARNING);
