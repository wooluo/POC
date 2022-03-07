#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111209);
  script_version("1.15");
  script_cvs_date("Date: 2019/04/30 14:00:04");

  script_cve_id(
    "CVE-2018-1275",
    "CVE-2018-2893",
    "CVE-2018-2894",
    "CVE-2018-2933",
    "CVE-2018-2935",
    "CVE-2018-2987",
    "CVE-2018-2998",
    "CVE-2018-7489"
  );
  script_bugtraq_id(
    103771,
    103203,
    104817
  );

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (July 2018 CPU)");
  script_summary(english:"Checks for the patch.");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebLogic Server installed on the remote host is
affected by multiple vulnerabilities:

  - An unspecified vulnerability in the Spring Framework
    (Sample Apps) subcomponent in Oracle WebLogic allows
    an unauthenticated, remote attacker to takeover a
    WebLogic server. (CVE-2018-1275)

  - An unspecified vulnerability in the WLS Core Components
    subcomponent in Oracle WebLogic allows an
    unauthenticated, remote attacker to takeover a
    WebLogic server. (CVE-2018-2893)

  - An unspecified vulnerability in the WLS - Web Services
    subcomponent in Oracle WebLogic allows an
    unauthenticated, remote attacker with HTTP access to
    compromise and takeover a WebLogic server.
    (CVE-2018-2894)

In addition, Oracle WebLogic Server is affected by several other lower
scoring vulnerabilities in the WLS Core Components, JSF, SAML, and 
Console (jackson-databind) subcomponents.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number."
  );
  # http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50f36723");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2018 Oracle
Critical Patch Update advisory.

Refer to Oracle for any additional patch instructions or
mitigation options.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1275");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Oracle WebLogic Server WLS File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");

  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by WebRAY, Inc. ");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  #script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("weblogic_version.inc");
include("obj.inc");
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
# individual security patches
if (version =~ "^12\.2\.1\.3($|[^0-9])")
{
  fix_ver = "12.2.1.3.180717";
  fix = make_list("27912627");
}
else if (version =~ "^12\.2\.1\.2($|[^0-9])")
{
  fix_ver = "12.2.1.2.180717";
  fix = make_list("27741413");
}
else if (version =~ "^12\.1\.3\.")
{
  fix_ver = "12.1.3.0.180717";
  fix = make_list("27919943");
}
else if (version =~ "^10\.3\.6\.")
{
  fix_ver = "10.3.6.0.180717";
  fix = make_list("B47X"); # patchid is obtained from the readme and 10.3.6.x assets are different 
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
