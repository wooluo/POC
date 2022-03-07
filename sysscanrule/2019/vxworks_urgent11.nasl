#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127108);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/05  9:28:46");

  script_cve_id(
    "CVE-2019-12255",
    "CVE-2019-12256",
    "CVE-2019-12257",
    "CVE-2019-12258",
    "CVE-2019-12259",
    "CVE-2019-12260",
    "CVE-2019-12261",
    "CVE-2019-12262",
    "CVE-2019-12263",
    "CVE-2019-12264",
    "CVE-2019-12265"
  );
  script_xref(name:"IAVA", value:"2019-A-0274");

  script_name(english:"Wind River VxWorks Multiple Vulnerabilities (URGENT/11)");
  script_summary(english:"Checks the OS fingerprint version.");

 script_set_attribute(attribute:"synopsis", value:
"The remote VxWorks device is potentially affected by multiple remote
code execution and denial-of-service vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote device is
potentially affected by multiple Wind River VxWorks remote code
execution and denial-of-service vulnerabilities in the IPnet TCP/IP
stack. An unauthenticated, remote, attacker could leverage these
vulnerabilities to gain full access to the affected device or to cause
the device to become unresponsive.

Note that GizaNE has not checked for the presence of the patch so this
finding may be a false positive.");
  # https://www.windriver.com/security/announcements/tcp-ip-network-stack-ipnet-urgent11/security-advisory-ipnet/
  script_set_attribute(attribute:"see_also", value:"");
  # https://go.armis.com/hubfs/White-papers/Urgent11%20Technical%20White%20Paper.pdf
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://armis.com/urgent11/");
    script_set_attribute(attribute:"solution", value:"Contact the device vendor to obtain the appropriate update");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12256");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/29");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:windriver:vxworks");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl");
  script_require_keys("Settings/ParanoidReport", "Host/OS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

os = get_kb_item_or_exit("Host/OS");
if ("VxWorks" >!< os) audit(AUDIT_OS_NOT, "VxWorks");

match = pregmatch(pattern:"VxWorks ([0-9][0-9.]*)", string:os);
if (isnull(match)) exit(1, "Failed to identify the version of VxWorks.");
version = match[1];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln = FALSE;

if (version =~ "^6($|\.)" && ver_compare(ver:version, fix:'6.5', strict:FALSE) >= 0 &&
    ver_compare(ver:version, fix:"6.9.4.11", strict:FALSE) <= 0)
{
  vuln = TRUE;
}
else if (version =~ "^7($|\.)")
{
  vuln = TRUE;
}

if (vuln)
{
  report =
    '\n    Version       : ' + version +
    '\n    Fixed Version : Consult Vendor' +
    '\n';

  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_OS_RELEASE_NOT, "VxWorks", version);
