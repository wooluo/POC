##
# 
##

include('compat.inc');

if (description)
{
  script_id(141807);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/26");

  script_cve_id(
    "CVE-2019-17267",
    "CVE-2020-9488",
    "CVE-2020-11022",
    "CVE-2020-14757",
    "CVE-2020-14820",
    "CVE-2020-14825",
    "CVE-2020-14841",
    "CVE-2020-14859",
    "CVE-2020-14882",
    "CVE-2020-14883"
  );
  script_xref(name:"IAVA", value:"2020-A-0478");

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (Oct 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of WebLogic Server installed on the remote host is affected by multiple vulnerabilities as referenced in
the October 2020 CPU advisory.

  - An unspecified vulnerability exists in the Console component. An unauthenticated, remote attacker with
    network access via HTTP can exploit this issue to compromise the server. Successful attacks of this 
    vulnerability can result in takeover of Oracle WebLogic Server. (CVE-2020-14882)

  - An unspecified vulnerability exists in the Core component. An unauthenticated, remote attacker can exploit 
    this issue via the IIOP and T3 protocols to compromise the server. Successful attacks of this
    vulnerability can result in takeover of Oracle WebLogic Server. (CVE-2020-14859)

  - An unspecified vulnerability exists in the Core component. An unauthenticated, remote attacker can exploit
    this issue via the IIOP protocol to compromise the server. Successful attacks of this vulnerability can
    result in takeover of Oracle WebLogic Server. (CVE-2020-14841)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2020 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14859");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
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
include('install_func.inc');

app_name = 'Oracle WebLogic Server';

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
port = install["port"];

fix = NULL;
fix_ver = NULL;

if (version =~ "^14\.1\.1\.0($|[^0-9])")
{
  fix_ver = '14.1.1.0.200930';
  fix = make_list('31957062');
}
else if (version =~ "^12\.2\.1\.4($|[^0-9])")
{
  fix_ver = '12.2.1.4.201001';
  fix = '31960985';
}
else if (version =~ "^12\.2\.1\.3($|[^0-9])")
{
  fix_ver = '12.2.1.3.201001';
  fix = make_list('31961038');
}
else if (version =~ "^12\.1\.3\.")
{
  fix_ver = '12.1.3.0.201020';
  fix = make_list('31656851');
}
else if (version =~ "^10\.3\.6\.")
{
  fix_ver = '10.3.6.0.201020';
  fix = make_list('NA7A');
}

if (isnull(fix_ver) || ver_compare(ver:version, fix:fix_ver, strict:FALSE) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, install['path']);

else {
  report =
    '\n  Oracle Home    : ' + install['Oracle Home'] +
    '\n  Install path   : ' + install['path'] +
    '\n  Version        : ' + version +
    '\n  Fixes          : ' + join(sep:', ', fix);
  security_report_v4(extra:report, severity:SECURITY_HOLE, port:port);
}

