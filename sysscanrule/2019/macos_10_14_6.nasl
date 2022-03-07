#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127054);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:39");

  script_cve_id(
    "CVE-2018-16860",
    "CVE-2018-19860",
    "CVE-2019-8641",
    "CVE-2019-8644",
    "CVE-2019-8646",
    "CVE-2019-8648",
    "CVE-2019-8649",
    "CVE-2019-8656",
    "CVE-2019-8657",
    "CVE-2019-8658",
    "CVE-2019-8660",
    "CVE-2019-8661",
    "CVE-2019-8662",
    "CVE-2019-8663",
    "CVE-2019-8666",
    "CVE-2019-8667",
    "CVE-2019-8669",
    "CVE-2019-8670",
    "CVE-2019-8671",
    "CVE-2019-8672",
    "CVE-2019-8673",
    "CVE-2019-8676",
    "CVE-2019-8677",
    "CVE-2019-8678",
    "CVE-2019-8679",
    "CVE-2019-8680",
    "CVE-2019-8681",
    "CVE-2019-8683",
    "CVE-2019-8684",
    "CVE-2019-8685",
    "CVE-2019-8686",
    "CVE-2019-8687",
    "CVE-2019-8688",
    "CVE-2019-8689",
    "CVE-2019-8690",
    "CVE-2019-8691",
    "CVE-2019-8692",
    "CVE-2019-8693",
    "CVE-2019-8694",
    "CVE-2019-8695",
    "CVE-2019-8697",
    "CVE-2019-13118"
  );
  
  script_xref(name:"APPLE-SA", value:"HT210348");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-07-17");
  script_xref(name:"IAVA", value:"2019-A-0260");

  script_name(english:"macOS 10.14.x < 10.14.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mac OS X / macOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 10.14.x prior to 10.14.6. It is, therefore, affected by
multiple vulnerabilities :

  - An application may be able to read restricted memory
    (CVE-2019-8691, CVE-2019-8692, CVE-2019-8693)

  - Extracting a zip file containing a symbolic link to an
    endpoint in an NFS mount that is attacker controlled may
    bypass Gatekeeper (CVE-2019-8656)

  - A remote attacker may be able to cause arbitrary code
    execution (CVE-2019-8648, CVE-2018-19860, CVE-2019-8661)

  - A remote attacker may be able to leak memory
    (CVE-2019-8646, CVE-2019-8663)

  - A remote attacker may be able to cause unexpected
    application termination or arbitrary code execution
    (CVE-2019-8641, CVE-2019-8660)

  - An application may be able to execute arbitrary code
    with system privileges (CVE-2019-8695, CVE-2019-8697)

  - An issue existed in Samba that may allow attackers to
    perform unauthorized actions by intercepting
    communications between services (CVE-2018-16860)

  - An application may be able to execute arbitrary code
    with kernel privileges (CVE-2019-8694)

  - A remote attacker may be able to view sensitive
    information (CVE-2019-13118)

  - An attacker may be able to trigger a use-after-free in
    an application deserializing an untrusted NSDictionary
    (CVE-2019-8662)

  - Visiting a malicious website may lead to address bar
    spoofing (CVE-2019-8670)

  - The encryption status of a Time Machine backup may be
    incorrect (CVE-2019-8667)

  - Parsing a maliciously crafted office document may lead
    to an unexpected application termination or arbitrary
    code execution (CVE-2019-8657)

  - Processing maliciously crafted web content may lead to
    universal cross site scripting (CVE-2019-8690,
    CVE-2019-8649, CVE-2019-8658)

  - Processing maliciously crafted web content may lead to
    arbitrary code execution (CVE-2019-8644, CVE-2019-8666,
    CVE-2019-8669, CVE-2019-8671, CVE-2019-8672,
    CVE-2019-8673, CVE-2019-8676, CVE-2019-8677,
    CVE-2019-8678, CVE-2019-8679, CVE-2019-8680,
    CVE-2019-8681, CVE-2019-8683, CVE-2019-8684,
    CVE-2019-8685, CVE-2019-8686, CVE-2019-8687,
    CVE-2019-8688, CVE-2019-8689)

Note that GizaNE has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210348");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS version 10.14.6 or later");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19860");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

fix = "10.14.6";
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
    severity:SECURITY_WARNING,
    extra:
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n'
    );
}
else audit(AUDIT_INST_VER_NOT_VULN, "macOS / Mac OS X", version);
