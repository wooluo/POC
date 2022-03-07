#
# 
#

include('compat.inc');

if (description)
{
  script_id(135680);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/24");

  script_cve_id(
    "CVE-2019-16943",
    "CVE-2019-17359",
    "CVE-2019-17571",
    "CVE-2020-2766",
    "CVE-2020-2798",
    "CVE-2020-2801",
    "CVE-2020-2811",
    "CVE-2020-2828",
    "CVE-2020-2829",
    "CVE-2020-2867",
    "CVE-2020-2869",
    "CVE-2020-2883",
    "CVE-2020-2884",
    "CVE-2020-2963"
  );
  script_xref(name:"IAVA", value:"2020-A-0153");

  script_name(english:"Oracle WebLogic Server (Apr 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the CPUApr2020 advisory.

  - A remote code execution vulnerability exists in the Log4j SocketServer class due to unsafe deserialization of
    untrusted data. An unauthenticated, remote attacker can exploit this to remotely execute arbitrary code when
    combined with a deserialization gadget when listening to untrusted network traffic for log data. This affects Log4j
    versions up to 1.2 up to 1.2.17. (CVE-2019-17571)

  - An information disclosure vulnerability exists in the Console component. An unauthenticated, remote attacker can
    exploit this to gain unauthorized read access to a subset of Oracle WebLogic Server accessible data. (CVE-2020-2766)

  - A vulnerability in the WLS Web Services component exists. An authenticated, remote attacker can exploit this via T3
    to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle
    WebLogic Server. (CVE-2020-2798)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2020 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17571");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('install_func.inc');
include('obj.inc');
include('spad_log_func.inc');

app_name = "Oracle WebLogic Server";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
ohome = install["Oracle Home"];
subdir = install["path"];
version = install["version"];
port = install["port"];

fix = NULL;
fix_ver = NULL;

spad_log(message:"checking version [" + version + "]");
# individual security patches
if (version =~ "^12\.2\.1\.4($|[^0-9])")
{
  fix_ver = "12.2.1.4.200228";
  fix = make_list("30970477", "30761841", "31101341");
}
else if (version =~ "^12\.2\.1\.3($|[^0-9])")
{
  fix_ver = "12.2.1.3.200227"; 
  fix = make_list("30965714");
}
else if (version =~ "^12\.1\.3\.")
{
  fix_ver = "12.1.3.0.200414";
  fix = make_list("30857795");
}
else if (version =~ "^10\.3\.6\.")
{
  fix_ver = "10.3.6.0.200414";
  # patchid is obtained from the readme and 10.3.6.x assets are different
  fix = make_list("Q3ZB"); 
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, subdir);

spad_log(message:"checking fix [" + obj_rep(fix) + "]");

# Modified the logic below to check that all patches in the fix list are applied 
# Iterate over the list of patches and check install for the patchID
PATCHED=TRUE;
foreach id (fix)
{
  spad_log(message:"Checking fix id: [" + id +"]");
  if (!install[id])
  {
    PATCHED=FALSE;
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
