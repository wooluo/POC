#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121226);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/30 14:00:04");

  script_cve_id(
      "CVE-2015-1832",
      "CVE-2018-1313",
      "CVE-2018-3246",
      "CVE-2018-1000180",
      "CVE-2018-1000613",
      "CVE-2019-2395",
      "CVE-2019-2398",
      "CVE-2019-2418",
      "CVE-2019-2441",
      "CVE-2019-2452"
  );
  script_bugtraq_id(
    93132,
    104140,
    105628,
    106585,
    106617
  );

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (January 2019 CPU)");
  script_summary(english:"Checks for the patch.");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebLogic Server installed on the remote host is
affected by multiple vulnerabilities:

  - XML external entity (XXE) vulnerability in the SqlXmlUtil code
    in Apache Derby before 10.12.1.1, when a Java Security Manager
    is not in place, allows context-dependent attackers to read
    arbitrary files or cause a denial of service (resource
    consumption) via vectors involving XmlVTI and the XML datatype.
    (CVE-2015-1832)

  - Bouncy Castle BC 1.54 - 1.59, BC-FJA 1.0.0, BC-FJA 1.0.1 and
    earlier have a flaw in the Low-level interface to RSA key pair
    generator, specifically RSA Key Pairs generated in low-level API
    with added certainty may have less M-R tests than expected. This
    appears to be fixed in versions BC 1.60 beta 4 and later,
    BC-FJA 1.0.2 and later. (CVE-2018-1000180)

  - Vulnerability in the Oracle WebLogic Server component of Oracle
    Fusion Middleware (subcomponent: WLS Core Components). Supported
    versions that are affected are 10.3.6.0, 12.1.3.0 and 12.2.1.3.
    Easily exploitable vulnerability allows high privileged attacker
    with network access via HTTP to compromise Oracle WebLogic
    Server. Successful attacks of this vulnerability can result in
    unauthorized creation, deletion or modification access to
    critical data or all Oracle WebLogic Server accessible data as
    well as unauthorized read access to a subset of Oracle WebLogic
    Server accessible data and unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of Oracle WebLogic
    Server. (CVE-2019-2452)

  - Vulnerability in the Oracle WebLogic Server component of Oracle
    Fusion Middleware (subcomponent: WLS Core Components). Supported
    versions that are affected are 10.3.6.0, 12.1.3.0 and 12.2.1.3.
    Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via T3 to compromise Oracle
    WebLogic Server. While the vulnerability is in Oracle WebLogic
    Server, attacks may significantly impact additional products.
    Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Oracle
    WebLogic Server accessible data as well as unauthorized read
    access to a subset of Oracle WebLogic Server accessible data and
    unauthorized ability to cause a partial denial of service
    (partial DOS) of Oracle WebLogic Server. (CVE-2019-2418)

  - Vulnerability in the Oracle WebLogic Server component of Oracle
    Fusion Middleware (subcomponent: WLS - Web Services). The
    supported version that is affected is 10.3.6.0. Easily
    exploitable vulnerability allows low privileged attacker with
    network access via HTTP to compromise Oracle WebLogic Server.
    Successful attacks of this vulnerability can result in
    unauthorized read access to a subset of Oracle WebLogic Server
    accessible data and unauthorized ability to cause a partial
    denial of service (partial DOS) of Oracle WebLogic Server.
    (CVE-2019-2395)

  - Vulnerability in the Oracle WebLogic Server component of Oracle
    Fusion Middleware (subcomponent: Application Container - JavaEE). 
    The supported version that is affected is 12.2.1.3. Easily
    exploitable vulnerability allows unauthenticated attacker
    with network access via HTTP to compromise Oracle WebLogic
    Server. Successful attacks of this vulnerability can result in
    unauthorized read access to a subset of Oracle WebLogic Server
    accessible data. (CVE-2019-2441)

  - Vulnerability in the Oracle WebLogic Server component of Oracle
    Fusion Middleware (subcomponent: WLS - Deployment). Supported
    versions that are affected are 10.3.6.0, 12.1.3.0 and 12.2.1.3.
    Easily exploitable vulnerability allows low privileged attacker
    with network access via HTTP to compromise Oracle WebLogic
    Server. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Oracle
    WebLogic Server accessible data. (CVE-2019-2398)

  - Legion of the Bouncy Castle Java Cryptography APIs versions prior
    to 1.60 are affected by CWE-470: Use of Externally-Controlled
    Input to Select Classes or Code ('Unsafe Reflection') flaw in
    XMSS/XMSS^MT private key deserialization routines. This allows
    an attacker to force execution of arbitrary code. Successful
    attack could be conducted via usage of a handcrafted private key
    object with references to unexpected classes which allow
    malicious commands execution. (CVE-2018-1000613)

  - Vulnerability in the Oracle WebLogic Server component of Oracle
    Fusion Middleware (subcomponent: WLS - Web Services). Supported
    versions that are affected are 12.1.3.0 and 12.2.1.3. Easily
    exploitable vulnerability allows unauthenticated attacker with
    network access via HTTP to compromise Oracle WebLogic Server.
    Successful attacks of this vulnerability can result in
    unauthorized access to critical data or complete access to all
    Oracle WebLogic Server accessible data. (CVE-2018-3246)

  - In Apache Derby 10.3.1.4 to 10.14.1.0, a specially-crafted
    network packet can be used to request the Derby Network Server
    to boot a database whose location and contents are under the
    user's control. If the Derby Network Server is not running with
    a Java Security Manager policy file, the attack is successful.
    If the server is using a policy file, the policy file must
    permit the database location to be read for the attack to work.
    The default Derby Network Server policy file distributed with
    the affected releases includes a permissive policy as the
    default Network Server policy, which allows the attack to work.
    (CVE-2018-1313)");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2019 Oracle
Critical Patch Update advisory.

Refer to Oracle for any additional patch instructions or
mitigation options.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000613");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("obj.inc");
include("spad_log_func.inc");

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
if (version =~ "^12\.2\.1\.3($|[^0-9])")
{
  fix_ver = "12.2.1.3.190115";
  fix = make_list("28710939");
}
else if (version =~ "^12\.1\.3\.")
{
  fix_ver = "12.1.3.0.190115";
  fix = make_list("28710923");
}
else if (version =~ "^10\.3\.6\.")
{
  fix_ver = "10.3.6.0.190115";
  fix = make_list("7HKN"); # patchid is obtained from the readme and 10.3.6.x assets are different
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
