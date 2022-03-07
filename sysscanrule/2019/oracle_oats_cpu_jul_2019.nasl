#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126788);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/19  9:48:46");

  script_cve_id("CVE-2016-1000031", "CVE-2019-2727");
  script_bugtraq_id(109183, 93604);
  script_xref(name:"TRA", value:"TRA-2016-12");

  script_name(english:"Oracle Application Testing Suite Multiple Vulnerabilities (Jul 2019 CPU)");
  script_summary(english:"Checks version of Oracle Application Testing suite");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Application Testing Suite installed on the remote host is affected by multiple vulnerabilities: 

  - A deserialization vulnerability exists in Apache Commons FileUpload library. An unauthenticated, remote attacker
    can exploit this, via customized Java serialised object, to execute arbitrary code on the target host.
    (CVE-2016-1000031)

  - An unspecified vulnerability in the Load Testing for Web Apps component of Oracle Application Testing Suite, which
    could allow an unauthenticated, remote attacker to read, update, or delete Oracle Application Testing Suite 
    accessible data and gives an ability to cause a partial denial of service (partial DOS). (CVE-2019-2727) ");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html#AppendixEM
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2019 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1000031");

  script_set_attribute(attribute:"vuln_publication_date",value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date",value:"2019/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/19");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:application_testing_suite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_application_testing_suite_installed.nbin");
  script_require_keys("installed_sw/Oracle Application Testing Suite");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('smb_func.inc');
include('install_func.inc');

app_name = 'Oracle Application Testing Suite';

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
ohome = install['Oracle Home'];
subdir = install['path'];
version = install['version'];

fix = NULL;
fix_ver = NULL;

# individual security patches
if (version =~ "^13\.3\.0\.1\.")
{
  fix_ver = '13.3.0.1.322';
  fix = '29920866';
}
else if (version =~ "^13\.2\.0\.1\.")
{
  fix_ver = '13.2.0.1.241';
  fix = '29920864';
}
else if (version =~ "^13\.1\.0\.1\.")
{
  fix_ver = '13.1.0.1.429';
  fix = '29907188';
}
else
  # flag all 12.5.0.3.x 
  fix_ver = '12.5.0.3.999999';

# Vulnerble versions that need to patch
if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1)
{
  report =
    '\n  Oracle home    : ' + ohome +
    '\n  Install path   : ' + subdir +
    '\n  Version        : ' + version;
  if (!isnull(fix))
    report += '\n  Required patch : ' + fix + '\n';
  else
    report +=
      '\n  Upgrade to 13.1.0.1 / 13.2.0.1 / 13.3.0.1 and apply the ' +
      'appropriate patch according to the July 2019 Oracle ' +
      'Critical Patch Update advisory.' +
      '\n';

  security_report_v4(extra:report, port:0, severity:SECURITY_HOLE);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, subdir);
