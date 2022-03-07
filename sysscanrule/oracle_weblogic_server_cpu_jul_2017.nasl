#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101815);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/10/19 15:39:22 $");

  script_cve_id(
    "CVE-2013-2027",
    "CVE-2017-5638",
    "CVE-2017-10063",
    "CVE-2017-10123",
    "CVE-2017-10137",
    "CVE-2017-10147",
    "CVE-2017-10148",
    "CVE-2017-10178"
  );
  script_bugtraq_id(
    78027,
    96729,
    99634,
    99644,
    99650,
    99651,
    99652,
    99653
);
  script_osvdb_id(
    118043,
    153025,
    161207,
    161209,
    161228,
    161229,
    161230,
    161231
  );
  script_xref(name:"CERT", value:"834067");
  script_xref(name:"EDB-ID", value:"41570");
  script_xref(name:"EDB-ID", value:"41614");

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (July 2017 CPU)");
  script_summary(english:"Checks for the patch.");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebLogic Server installed on the remote host is
affected by multiple vulnerabilities :

  - A flaw exists in Jython due to executable classes being
    created with insecure permissions. A local attacker can
    exploit this to bypass intended access restrictions and
    thereby disclose sensitive information or gain elevated
    privileges. (CVE-2013-2027)

  - A remote code execution vulnerability exists in the
    Apache Struts component in the Jakarta Multipart parser
    due to improper handling of the Content-Type,
    Content-Disposition, and Content-Length headers.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted header value in the HTTP
    request, to execute arbitrary code. (CVE-2017-5638)

  - An unspecified flaw exists in the Web Services component
    that allows an unauthenticated, remote attacker to have
    an impact on integrity and availability.
    (CVE-2017-10063)

  - An unspecified flaw exists in the Web Container
    component that allows an authenticated, remote attacker
    to disclose sensitive information. (CVE-2017-10123)

  - An unspecified flaw exists in the JNDI component that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-10137)

  - An unspecified flaw exists in the Core Components that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-10147)

  - An unspecified flaw exists in the Core Components that
    allows an unauthenticated, remote attacker to have an
    impact on integrity. (CVE-2017-10148)

  - An unspecified flaw exists in the Web Container
    component that allows an unauthenticated, remote
    attacker to have an impact on confidentiality and
    integrity. (CVE-2017-10178)");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2017 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts Jakarta Multipart Parser OGNL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 WebRAY Network Security, Inc.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  #script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("weblogic_version.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "Oracle WebLogic Server";
install = get_weblogic_install(exit_if_unknown_ver:TRUE);
ohome = install["Oracle Home"];
subdir = install["path"];
version = install["version"];
port = install["port"];

fix = NULL;
fix_ver = NULL;

# individual security patches
if (version =~ "^10\.3\.6\.")
{
  fix_ver = "10.3.6.0.170718";
  fix = "25869650";
}
else if (version =~ "^12\.1\.3\.")
{
  fix_ver = "12.1.3.0.170718";
  fix = "25869659";
}
else if (version =~ "^12\.2\.1\.1($|[^0-9])")
{
  fix_ver = "12.2.1.1.170718";
  fix = "25961827";
}
else if (version =~ "^12\.2\.1\.2($|[^0-9])")
{
  fix_ver = "12.2.1.2.170718";
  fix = "25871788";
}

if (!isnull(fix_ver) && ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1)
{
  report =
    '\n  Oracle home    : ' + ohome +
    '\n  Install path   : ' + subdir +
    '\n  Version        : ' + version +
    '\n  Required patch : ' + fix +
    '\n';
  security_report_v4(extra:report, port:port, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, subdir);
