#TRUSTED 4aa22985d5e18b15b2076de7c856179c63123a01960b5084ea5953c79e10c00eb1ab39c7e675146dd0118be74fd4ecf548bfb7b9980ae7102caf3beec40816d927ae85ad8ac452f5f5e41962cb08006ea83e63bfd0c51a5d908c1f313c12dd9b397ae84d860c065f831a3c6307fb9c62b07a4c54be2663676ffd63d9e2dea3f7104548658c5fbb8fb4b63894085872ebcd010b7f9abd42531c98693cc7c806f5b7ba8482f1b20b4f478381093bcfe9cac5d432a6c33169f381e2a6d3512377503fc355f9cdd339d1b4c539e8d989fab65564133e939e768684f545ba321eb52fcae5888a13e85e1c426e160e1b1aaa670f5ab7c29288c4876f89ed0377c8fe36680a768cee7e6ec4650ceb53e1c1e7e06290eccfe52093c667f779775df48a86a6893bb2eadcfed3af4995723352b9e49df98f3fd48d2027f88f031166fee8ae7565b5458e789e083b67e73b9b5bcf5ea5b91d4b64b530d1bc95fe6d12819d1ca4e0f415fa770de53cebe07b49a5788ba0a30a474c615cc67f75444b86ef55c91a7e68d432ef316001e71b504825dab277e18265e76bea77fb5e2c51fee302f3a7b4f6ad95d7311fa58961a67e4759f23b7902706859ec6ce4d574314533699becfd4621047e00476d5e4ce5cdde9d160156a6346cfa4e4f79d9a67fbc88715a032be32f24ee9ada3aaa9a8bc1d03f238e97f3a3b67d882b0e9154dd5ec2a3f4
#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(122508);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/03/01");

  script_cve_id(
    "CVE-2019-6223",
    "CVE-2019-7286",
    "CVE-2019-7288"
  );
  script_bugtraq_id(106951, 106962);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-02-07-2");

  script_name(english:"macOS 10.14.3 Supplemental Update");
  script_summary(english:"Check the version of Mac OS X / macOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update that fixes
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS 10.14.3 that is missing
the macOS 10.14.3 Supplemental Update.  This update fixes the
following vulnerabilities :

  - An unspecified flaw exists related to handling Group
    FaceTime calls that allows an attacker to cause a call
    recipient to unintentionally answer. (CVE-2019-6223)

  - An input-validation flaw exists related to the
    Foundation component that allows memory corruption and
    privilege escalation. (CVE-2019-7286)

  - An unspecified flaw exists related to Live Photos in
    FaceTime having unspecified impact. (CVE-2019-7288)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT209521");
  # https://lists.apple.com/archives/security-announce/2019/Feb/msg00001.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Install the macOS 10.14.3 Supplemental Update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7286");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS)
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X / macOS");
if (!preg(pattern:"Mac OS X 10\.14\.3([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "macOS 10.14.3");


# Get the product build version.
plist = "/System/Library/CoreServices/SystemVersion.plist";
cmd =
  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 ProductBuildVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
build = exec_cmd(cmd:cmd);
if (
  !strlen(build) ||
  build !~ "^18D[0-9]+$"
) exit(1, "Failed to extract the ProductBuildVersion from '"+plist+"'.");


if (build =~ "^18D([0-9]|[0-9][0-9]|10[0-8])$")
{
  report = '\n  Product version                 : ' + os +
           '\n  Installed product build version : ' + build +
           '\n  Fixed product build version     : 18D109' +
           '\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else exit(0, "The host has product build version "+build+" and is not affected.");
