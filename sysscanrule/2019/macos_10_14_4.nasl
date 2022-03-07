#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123128);
  script_version("1.5");
  script_cvs_date("Date: 2019/05/21  9:43:50");

  script_cve_id(
    "CVE-2018-12015",
    "CVE-2018-18311",
    "CVE-2018-18313",
    "CVE-2019-6207",
    "CVE-2019-6237",
    "CVE-2019-6239",
    "CVE-2019-7293",
    "CVE-2019-8502",
    "CVE-2019-8504",
    "CVE-2019-8507",
    "CVE-2019-8508",
    "CVE-2019-8510",
    "CVE-2019-8511",
    "CVE-2019-8513",
    "CVE-2019-8514",
    "CVE-2019-8516",
    "CVE-2019-8517",
    "CVE-2019-8519",
    "CVE-2019-8520",
    "CVE-2019-8521",
    "CVE-2019-8522",
    "CVE-2019-8526",
    "CVE-2019-8527",
    "CVE-2019-8529",
    "CVE-2019-8530",
    "CVE-2019-8533",
    "CVE-2019-8537",
    "CVE-2019-8540",
    "CVE-2019-8542",
    "CVE-2019-8545",
    "CVE-2019-8546",
    "CVE-2019-8549",
    "CVE-2019-8550",
    "CVE-2019-8552",
    "CVE-2019-8555",
    "CVE-2019-8561",
    "CVE-2019-8565"
  );
  script_bugtraq_id(
    104423,
    106072,
    106145
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-3-25-2");

  script_name(english:"macOS 10.14.x < 10.14.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mac OS X / macOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is
10.14.x prior to 10.14.4. It is, therefore, affected by multiple
vulnerabilities, including:

  - Mounting a maliciously crafted NFS network share may lead to
    arbitrary code execution with system privileges. (CVE-2019-8508)

  - An application may be able to execute arbitrary code with kernel
    privileges. (CVE-2019-8529)

  - A malicious application may be able to execute arbitrary code
    with system privileges (CVE-2019-8549)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT209600");
  # https://lists.apple.com/archives/security-announce/2019/Mar/msg00001.html 
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS version 10.14.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8508");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X Feedback Assistant Race Condition');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/OS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


fix = "10.14.4";
minver = "10.14";

os = get_kb_item("Host/MacOSX/Version");
if (!os)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Mac OS X" >!< os) audit(AUDIT_OS_NOT, "macOS / Mac OS X");

  c = get_kb_item("Host/OS/Confidence");
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) audit(AUDIT_OS_NOT, "macOS / Mac OS X");

matches = pregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
if (empty_or_null(matches)) exit(1, "Failed to parse the macOS / Mac OS X version ('" + os + "').");

version = matches[1];

if (ver_compare(ver:version, minver:minver, fix:fix, strict:FALSE) == -1)
{
  security_report_v4(
    port:0,
    severity:SECURITY_HOLE,
    extra:
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n'
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "macOS / Mac OS X", version);
