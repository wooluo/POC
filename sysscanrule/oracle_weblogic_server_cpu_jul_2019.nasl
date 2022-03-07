#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126915);
  script_version("1.4");
  script_cvs_date("Date: 2019/08/23 10:01:45");

  script_cve_id(
      "CVE-2016-7103",
      "CVE-2019-2725", 
      "CVE-2019-2729",       
      "CVE-2019-2824", 
      "CVE-2019-2827"       
  );
  script_bugtraq_id(
    107944
  );
  script_xref(name:"IAVA", value:"2019-A-0256");

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (Jul 2019 CPU)");
  script_summary(english:"Checks the version of Oracle WebLogic to ensure the July 2019 CPU is applied.");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebLogic Server installed on the remote host is
affected by multiple vulnerabilities:

  - An unspecified vulnerability allows a remote unauthenticated 
    attacker with network access to compromise and takeover the 
    StorageTek Tape Analytics SW Tool. (CVE-2019-2725) (CVE-2019-2729)

  - An unspecified vulnerability allows a remote unauthenticated 
    attacker with network access to compromise and takeover the 
    Tape Virtual Storage Manager GUI. (CVE-2019-2725)

  - An unspecified vulnerability in the WLS Core Component allows an 
    authenticated low privileged attacker with network 
    access via HTTP to compromise Oracle WebLogic Server, resulting 
    in unauthorized update, insert or delete access to Oracle 
    WebLogic Server accessible data. (CVE-2019-2824) (CVE-2019-2827)

  - An unspecified vulnerability in the jQuery Component allows an 
    authenticated low privileged attacker with network 
    access via HTTP to compromise Oracle WebLogic Server, resulting 
    in unauthorized update, insert or delete access to Oracle 
    WebLogic Server accessible data. Successful attacks require
    human interaction from actions from another Weblogic user.
    (CVE-2016-71030)
");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html 
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2019verbose-5072838.html#FMW
  script_set_attribute(attribute:"see_also", value:"");
  
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2019 Oracle
Critical Patch Update advisory.

Refer to Oracle for any additional patch instructions or
mitigation options.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2725");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Oracle Weblogic Server Deserialization RCE - AsyncResponseService');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  #script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('weblogic_version.inc');
include('obj.inc');
include('spad_log_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "Oracle WebLogic Server";
install = get_weblogic_install(exit_if_unknown_ver:TRUE);
ohome = install["Oracle Home"];
subdir = install["path"];
version = install["version"];
port = install["port"];

fix = NULL;
fix_ver = NULL;

spad_log(message:"checking version [" + version + "]");
# individual security patches
if (version =~ "^12\.2\.1\.3($|[^0-9])")
{
  fix_ver = "12.2.1.3.190522";
  fix = make_list("29814665");
}
else if (version =~ "^12\.1\.3\.")
{
  fix_ver = "12.1.3.0.190716";
  fix = make_list("29633448");
}
else if (version =~ "^10\.3\.6\.")
{
  fix_ver = "10.3.6.0.190716";
  fix = make_list("MXLE"); # patchid is obtained from the readme and 10.3.6.x assets are different
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, subdir);

spad_log(message:"checking fix [" + obj_rep(fix) + "]");
PATCHED=FALSE;

# Iterate over the list of patches and check the install for the patchID
foreach id (fix)
{
 spad_log(message:"Checking fix id: [" + id +"]");
 if (install[id])
 {
   PATCHED=TRUE;
   break;
 }
}

VULN=FALSE;
if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1)
  VULN=TRUE;

if (PATCHED || !VULN)
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, subdir);

report =
  '\n  Oracle Home    : ' + ohome +
  '\n  Install path   : ' + subdir +
  '\n  Version        : ' + version +
  '\n  Fixes          : ' + join(sep:", ", fix);

security_report_v4(extra:report, severity:SECURITY_HOLE, port:port);
