
##
# 
##



include('compat.inc');

if (description)
{
  script_id(151458);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/09");

  script_cve_id("CVE-2021-20579", "CVE-2021-29777");

  script_name(english:"IBM DB2 9.7 < 9.7 / 10.1 < 10.1 / 10.5 < 10.5 / 11.1 < 11.1.4 / 11.5 < 11.5.6 Multiple Vulnerabilities (Unix)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to it self-reported version number, IBM Db2 is affected by multiple vulnerabilities:

  - IBM Db2 for Linux, UNIX and Windows could allow an unauthenticated attacker to cause a denial of service due to a
    specific circumstance of a table being dropped while being accessed in another session. (CVE-2021-29777)

  - IBM Db2 db2fm is vulnerable to an information disclosure as it could allow a user who can create a view or inline 
    SQL function to obtain sensitive information when AUTO_REVAL is set to DEFFERED_FORCE. (CVE-2021-20579)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6466369");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6466373");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Fix Pack or Special Build based on the most recent fix pack level for your branch.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20579");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_installed.nbin");
  script_require_keys("installed_sw/DB2 Server");
  script_exclude_keys("SMB/db2/Installed");

  exit(0);
}

include('install_func.inc');
include('db2_report_func.inc');

# The remote host's OS is Windows, not Linux.
if (get_kb_item('SMB/db2/Installed')) audit(AUDIT_OS_NOT, 'Linux', 'Windows');

var app = 'DB2 Server';
var install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

var port = install['port'];
if (!port) port = 0;

# DB2 has an optional OpenSSH server that will run on 
# windows.  We need to exit out if we picked up the windows
# installation that way.
if ('Windows' >< install['platform'])
  audit(AUDIT_HOST_NOT, 'a Linux based operating system');

var version = kb_version = install['version'];

var path = install['path'];

var special_build = install['special_build'];
if (empty_or_null(special_build)) special_build = 'None';
if (special_build != 'None') kb_version += ' with Special Build ' + special_build;

var fix_ver = NULL;
var fix_build = NULL;

if (version =~ "^9\.7\.")
{
  fix_ver = '9.7.0.11';
  fix_build = '40801';
}
else if (version =~ "^10\.1\.")
{
  fix_ver = '10.1.0.6';
  fix_build = '40800';
}
else if (version =~ "^10\.5\.")
{
  fix_ver = '10.5.0.11';
  fix_build = '40802';
}
else if (version =~ "^11\.1\.")
{
  fix_ver = '11.1.4.6';
  fix_build = '40812';
}
else if (version =~ "^11\.5\.") {
  fix_ver = '11.5.6.0';
}
else {
  audit(AUDIT_INST_PATH_NOT_VULN, app, kb_version, path);
}

var vuln = FALSE;
var cmp = ver_compare(ver:version, fix:fix_ver, strict:FALSE);

# less than current fix pack                                      
if (cmp < 0)
  vuln = TRUE;
else if (cmp == 0 && !isnull(fix_build))
{
  # missing special build or less than current special build      
  if (special_build == 'None' || ver_compare(ver:special_build, fix:fix_build, strict:FALSE) < 0)
    vuln = TRUE;
}

if (!vuln)
  audit(AUDIT_INST_PATH_NOT_VULN, app, kb_version, path);

report_db2(
  severity          : SECURITY_NOTE,
  port              : port,
  product           : app,
  path              : path,
  installed_version : version,
  fixed_version     : fix_ver,
  special_installed : special_build,
  special_fix       : fix_build
);
