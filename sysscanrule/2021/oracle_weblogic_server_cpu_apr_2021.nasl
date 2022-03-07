##
# 
##

include('compat.inc');

if (description)
{
  script_id(148924);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/22");

  script_cve_id(
    "CVE-2019-3740",
    "CVE-2019-10086",
    "CVE-2020-25649",
    "CVE-2021-2135",
    "CVE-2021-2136",
    "CVE-2021-2142",
    "CVE-2021-2157",
    "CVE-2021-2204",
    "CVE-2021-2211",
    "CVE-2021-2214",
    "CVE-2021-2294"
  );

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (Apr 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of WebLogic Server installed on the remote host is affected by multiple vulnerabilities as referenced in
the April 2021 CPU advisory.

  - An unspecified vulnerability exists in the Coherence Container component. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server.
    Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. (CVE-2021-2135)

  - An unspecified vulnerability exists in the Core component. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful
    attacks of this vulnerability can result in takeover of Oracle WebLogic Server. (CVE-2021-2136)
    
  - An unspecified vulnerability exists in the TopLink Integration component. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all Oracle WebLogic Server accessible data. (CVE-2021-2157)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2135");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/22");

  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include('install_func.inc');

var app_name = 'Oracle WebLogic Server';

var os = get_kb_item_or_exit('Host/OS');
var port;
if ('windows' >< tolower(os))
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;
}
else port = 0;

var install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
var version = install['version'];

var fix = NULL;
var fix_ver = NULL;

if (version =~ "^14\.1\.1\.0($|[^0-9])")
{
  fix_ver = '14.1.1.0.210329';
  fix = make_list('32697788');
}
else if (version =~ "^12\.2\.1\.4($|[^0-9])")
{
  fix_ver = '12.2.1.4.210330';
  fix = make_list('32698246');
}
else if (version =~ "^12\.2\.1\.3($|[^0-9])")
{
  fix_ver = '12.2.1.3.210329';
  fix = make_list('32697734');
}
else if (version =~ "^12\.1\.3\.")
{
  fix_ver = '12.1.3.0.210420';
  fix = make_list('32345262');
}
else if (version =~ "^10\.3\.6\.")
{
  fix_ver = '10.3.6.0.210420';
  fix = make_list('AXXI');
}

if (isnull(fix_ver) || ver_compare(ver:version, fix:fix_ver, strict:FALSE) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, install['path']);

else {
  var report =
    '\n  Oracle Home    : ' + install['Oracle Home'] +
    '\n  Install path   : ' + install['path'] +
    '\n  Version        : ' + version +
    '\n  Fixes          : ' + join(sep:', ', fix);
  security_report_v4(extra:report, severity:SECURITY_HOLE, port:port);
}

