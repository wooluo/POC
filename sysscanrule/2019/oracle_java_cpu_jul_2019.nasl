#
# (C) WebRAY Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126821);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/19 14:00:51");

  script_cve_id(
    "CVE-2019-2745",
    "CVE-2019-2762",
    "CVE-2019-2766",
    "CVE-2019-2769",
    "CVE-2019-2786",
    "CVE-2019-2816",
    "CVE-2019-2818",
    "CVE-2019-2821",
    "CVE-2019-2842",
    "CVE-2019-6129",
    "CVE-2019-7317"
  );
  script_bugtraq_id(
    108098,
    109184,
    109185,
    109186,
    109187,
    109188,
    109189,
    109201,
    109206,
    109210,
    109212
  );
  script_xref(name:"IAVA", value:"2019-A-0255");

  script_name(english:"Oracle Java SE 1.7.0_231 / 1.8.0_221 / 1.11.0_4 / 1.12.0_2 Multiple Vulnerabilities (Jul 2019 CPU)");
  script_summary(english:"Checks the version of the JRE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 7 Update 231, 8 Update 221,
11 Update 4, or 12 Update 2. It is, therefore, affected by multiple
vulnerabilities:

  - Unspecified vulnerabilities in the utilities and JCE 
    subcomponents of Oracle Java SE, which could allow an 
    unauthenticated remote attacker to cause a partial denial 
    of service. (CVE-2019-2762, CVE-2019-2769, CVE-2019-2842)

  - An unspecified vulnerability in the security subcomponent 
    of Oracle Java SE, which could allow an unauthenticated 
    local attacker to gain unauthorized access to critical Java 
    SE data. (CVE-2019-2745)

  - Unspecified vulnerabilities in the networking and security 
    subcomponents of Oracle Java SE, which could allow an 
    unauthenticated remote attacker to gain unauthorized 
    access to Java SE data. Exploitation of this vulnerability 
    requires user interaction. 
    (CVE-2019-2766, CVE-2019-2786, CVE-2019-2818)

  - An unspecified vulnerability in the networking subcomponent
    of Oracle Java SE, which could allow an unauthenticated 
    remote attacker unauthorized read, update, insert or
    delete access to Java SE data. (CVE-2019-2816)

  - An unspecified vulnerability in the JSSE subcomponent of 
    Oracle Java SE, which could allow an unauthenticated, 
    remote attacker to gain unauthorized access to critical
    Java SE data. Exploitation of this vulnerability requires 
    user interaction. (CVE-2019-2821)

  - A use after free vulnerability exists in the libpng 
    subcomponent of Oracle Java SE. An unauthenticated, 
    remote attacker can exploit this to cause a complete
    denial of service condition in Java SE. Exploitation 
    of this vulnerability requires user interaction.
    (CVE-2019-7317)

GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number."
);
  # https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 12 Update 2 , 11 Update 4, 8 Update 221
/ 7 Update 231 or later. If necessary, remove any affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2762");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_keys("SMB/Java/JRE/Installed");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

# Check each installed JRE.
installs = get_kb_list_or_exit('SMB/Java/JRE/*');

info = '';
vuln = 0;
installed_versions = '';

foreach install (list_uniq(keys(installs)))
{
  ver = install - 'SMB/Java/JRE/';
  if (ver !~ "^[0-9.]+") continue;

  installed_versions = installed_versions + ' & ' + ver;

  # Fixes : (JDK|JRE) 12 Update 2 / 11 Update 4 / 8 Update 221 / 7 Update 231 
  if (
    ver_compare(minver:'1.7.0', ver:ver, fix:'1.7.0_231', regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:'1.8.0', ver:ver, fix:'1.8.0_221', regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:'1.11.0', ver:ver, fix:'1.11.0_4', regexes:{0:"_(\d+)"}, strict:FALSE) < 0 ||
    ver_compare(minver:'1.12.0', ver:ver, fix:'1.12.0_2', regexes:{0:"_(\d+)"}, strict:FALSE) < 0
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.7.0_231 / 1.8.0_221 / 1.11.0_4 / 1.12.0_2\n';
  }
}

# Report if any were found to be vulnerable.
if (info)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (vuln > 1) s = 's of Java are';
  else s = ' of Java is';

  report =
    '\n' +
    'The following vulnerable instance'+s+' installed on the\n' +
    'remote host :\n' +
    info;
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else
{
  installed_versions = substr(installed_versions, 3);
  if (' & ' >< installed_versions)
    exit(0, 'The Java '+installed_versions+' installations on the remote host are not affected.');
  else
    audit(AUDIT_INST_VER_NOT_VULN, 'Java', installed_versions);
}
