#
# 
#

include('compat.inc');

if (description)
{
  script_id(138332);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/31");

  script_cve_id(
    "CVE-2020-4355",
    "CVE-2020-4363",
    "CVE-2020-4386",
    "CVE-2020-4387",
    "CVE-2020-4414",
    "CVE-2020-4420"
  );
  script_xref(name:"IAVB", value:"2020-B-0035");

  script_name(english:"IBM DB2 9.7 < FP11 40162 / 10.1 < FP6 40161 / 10.5 < FP11 40160 / 11.1 < FP5 40159 / 11.5 < Mod 4 FP0 Multiple Vulnerabilities (UNIX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the remote host is either 9.7 prior to Fix Pack 11
Special Build 40162, 10.1 prior to Fix Pack 6 Special Build 40161, 10.5 prior to Fix Pack 11 Special Build 40160, or
11.1 prior to Fix Pack 5 Special Build 40159, 11.5 prior to Mod 4 Fix Pack 0. It is, therefore,
affected by one or more of the following vulnerabilities:

  - IBM DB2 for Linux, UNIX and Windows (includes DB2 Connect Server) 9.7, 10.1, 10.5, 11.1, and 11.5 is
    vulnerable to a denial of service, caused by improper handling of Secure Sockets Layer (SSL) renegotiation
    requests. By sending specially-crafted requests, a remote attacker could exploit this vulnerability to
    increase the resource usage on the system. (CVE-2020-4355)

  - IBM DB2 for Linux, UNIX and Windows (includes DB2 Connect Server) 9.7, 10.1, 10.5, 11.1, and 11.5 is
    vulnerable to a buffer overflow, caused by improper bounds checking which allows a local attacker to
    execute arbitrary code on the system with root privileges. (CVE-2020-4363)

  - IBM DB2 for Linux, UNIX and Windows (includes DB2 Connect Server) 9.7, 10.1, 10.5, 11.1, and 11.5 allows a
    local user to obtain sensitive information using a race condition of a symbolic link. (CVE-2020-4386,
    CVE-2020-4387)

  - IBM DB2 for Linux, UNIX and Windows (includes DB2 Connect Server) 9.7, 10.1, 10.5, 11.1, and 11.5 allows a
    local attacker to perform unauthorized actions on the system, caused by improper usage of shared memory.
    By sending a specially-crafted request, an attacker can exploit this vulnerability to obtain sensitive
    information or cause a denial of service (DoS). (CVE-2020-4414)

  - IBM DB2 for Linux, UNIX and Windows (includes DB2 Connect Server) 9.7, 10.1, 10.5, 11.1, and 11.5 could
    allow an unauthenticated attacker to cause a denial of service due a hang in the execution of a terminate
    command. (CVE-2020-4420)
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6242342");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6242332");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6242336");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6242350");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6242356");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6242362");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Fix Pack or Special Build based on the most recent fix pack level for your branch.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4363");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_installed.nbin");
  script_require_keys("installed_sw/DB2 Server");
  script_exclude_keys("SMB/db2/Installed");

  exit(0);
}

include('install_func.inc');
include('db2_report_func.inc');

# The remote host's OS is Windows, not Linux.
if (get_kb_item('SMB/db2/Installed')) audit(AUDIT_OS_NOT, 'Linux', 'Windows');

app = 'DB2 Server';
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
port = install['port'];
if (!port) port = 0;

# DB2 has an optional OpenSSH server that will run on 
# windows.  We need to exit out if we picked up the windows
# installation that way.
if ('Windows' >< install['platform'])
  audit(AUDIT_HOST_NOT, 'a Linux based operating system');

version = kb_version = install['version'];

path = install['path'];

special_build = install['special_build'];
if (empty_or_null(special_build)) special_build = 'None';
if (special_build != 'None') kb_version += ' with Special Build ' + special_build;

fix_ver = NULL;
fix_build = NULL;

if (version =~ '^9\\.7\\.')
{
  fix_ver = '9.7.0.11';
  fix_build = '40162';
}
else if (version =~ '^10\\.1\\.')
{
  fix_ver = '10.1.0.6';
  fix_build = '40161';
}
else if (version =~ '^10\\.5\\.')
{
  fix_ver = '10.5.0.11';
  fix_build = '40160';
}
else if (version =~ '^11\\.1\\.')
{
  fix_ver = '11.1.4.5';
  fix_build = '40159';
}
else if (version =~ '^11\\.5\\.')
  fix_ver = '11.5.4.0';
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, kb_version, path);

vuln = FALSE;
cmp = ver_compare(ver:version, fix:fix_ver, strict:FALSE);
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
  severity          : SECURITY_HOLE,
  port              : port,
  product           : app,
  path              : path,
  installed_version : version,
  fixed_version     : fix_ver,
  special_installed : special_build,
  special_fix       : fix_build
);
