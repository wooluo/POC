#
# 
#

include('compat.inc');

if (description)
{
  script_id(138592);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/28");

  script_cve_id(
    "CVE-2017-5645",
    "CVE-2018-11058",
    "CVE-2020-2966",
    "CVE-2020-2967",
    "CVE-2020-5398",
    "CVE-2020-9546",
    "CVE-2020-14557",
    "CVE-2020-14572",
    "CVE-2020-14588",
    "CVE-2020-14589",
    "CVE-2020-14622",
    "CVE-2020-14625",
    "CVE-2020-14644",
    "CVE-2020-14645",
    "CVE-2020-14652",
    "CVE-2020-14687"
  );
  script_bugtraq_id(97702, 108106);
  script_xref(name:"IAVA", value:"2020-A-0327");

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (Jul 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of WebLogic Server installed on the remote host is affected by multiple vulnerabilities as referenced in
the July 2020 CPU advisory.

  - A vulnerability Centralized Thirdparty Jars (jackson-databind) exists. An unauthenticated, remote attacker
    can exploit this issue via the HTTP protocol to takeover the Oracle WebLogic Server. (CVE-2020-9546)

  - A vulnerability in the Core component exists. An unauthenticated, remote attacker can exploit this issue
    via the IIOP and T3 protocols to takeover the Oracle WebLogic Server. (CVE-2020-14687)

  - A vulnerability in the Core component exists. An unauthenticated, remote attacker can exploit this issue
    via the IIOP and T3 protocols to takeover the Oracle WebLogic Server. (CVE-2020-14645)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2020 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5398");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/17");

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
include('install_func.inc');

app_name = 'Oracle WebLogic Server';

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
port = install["port"];

fix = NULL;
fix_ver = NULL;

if (version =~ "^14\.1\.1\.")
{
  fix_ver = '14.1.1.0.200624';
  fix = make_list('31532352');
}

if (version =~ "^12\.2\.1\.4($|[^0-9])")
{
  fix_ver = '12.2.1.4.200624';
  fix = make_list('31537019', '31544353');
}

else if (version =~ "^12\.2\.1\.3($|[^0-9])")
{
  fix_ver = '12.2.1.3.200624';
  fix = make_list('31535411', '31544340');
}
else if (version =~ "^12\.1\.3\.")
{
  fix_ver = '12.1.3.0.200714';
  fix = make_list('31178516', '31544340');
}
else if (version =~ "^10\.3\.6\.")
{
  fix_ver = '10.3.6.0.200714';
  fix = make_list('I37G', 'TYIA');
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
