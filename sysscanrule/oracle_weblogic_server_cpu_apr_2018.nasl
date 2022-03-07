#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109201);
  script_version("1.18");
  script_cvs_date("Date: 2019/04/30 14:00:04");

  script_cve_id("CVE-2018-2628", "CVE-2013-1768", "CVE-2017-5645");
  script_bugtraq_id( 97702, 60534);

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (April 2018 CPU)");
  script_summary(english:"Checks for the patch.");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebLogic Server installed on the remote host is
affected by multiple vulnerabilities ");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e39ef65");
  # https://www.tenable.com/blog/critical-oracle-weblogic-server-flaw-still-not-patched
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9cf2dde7");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2018 Oracle
Critical Patch Update advisory.

Note that the patch for CVE-2018-2628 is reportedly incomplete.
Refer to Oracle for any additional patch instructions or
mitigation options.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2628");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Oracle Weblogic Server Deserialization RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");


  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/20");

  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by WebRAY, Inc.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  #script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("weblogic_version.inc");
include("spad_log_func.inc");

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
if (version =~ "^10\.3\.6\.0")
{
  fix_ver = "10.3.6.0.180417";
  fix = make_list('GFWX', 'B47X'); # Smart Patch Update ID, only 10.3.6.0 has a smart patch update id
}
else if (version =~ "^12\.1\.3\.0")
{
  fix_ver = "12.1.3.0.180417";
  fix = make_list("27419391", "27919943");
}
else if (version =~ "^12\.2\.1\.2")
{
  fix_ver = "12.2.1.2.180417";
  fix = make_list("27338939","27741413");
}
else if (version =~ "^12\.2\.1\.3")
{
  fix_ver = "12.2.1.3.180417";
  fix = make_list("27342434", "27912627");
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
