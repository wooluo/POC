#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127910);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/16 17:09:35");

  script_cve_id("CVE-2019-1161");
  script_xref(name:"IAVA", value:"2019-A-0294");

  script_name(english:"Microsoft Defender Elevation of Privilege Vulnerability (CVE-2019-1161)");
  script_summary(english:"Checks the MpSigStub.exe version.");

  script_set_attribute(attribute:"synopsis", value:
"An antimalware application installed on the remote host is affected by
an elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Malware Protection Signature Update Stub (MpSigStub.exe) installed on the remote Windows host
is prior to 1.1.16200.1. It is, therefore, affected by a elevation of privilege vulnerability which could allow an
attacker who successfully exploited this vulnerability to elevate privileges on the system.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1161
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Enable automatic updates to update the scan engine for the relevant antimalware applications. Refer to Knowledge Base
Article 2510781 for information on how to verify that MMPE has been updated.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1161");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_defender");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

app = 'Microsoft Malware Protection Signature Update Stub';
winroot = NULL;
mpsigstub_path = NULL;
version = NULL;
fix = "1.1.16200.1";

get_kb_item_or_exit("SMB/Registry/Enumerated");

winroot = hotfix_get_systemroot();
if (!winroot) exit(1, "Failed to get the system root.");

mpsigstub_path =  winroot + "\System32\MpSigStub.exe";

ver = hotfix_get_fversion(path:mpsigstub_path);
if (ver['error'] != HCF_OK) audit(AUDIT_NOT_DETECT, app);

version = join(ver['value'], sep:'.');

if (ver_compare(ver:version, fix:fix) < 0)
{
  report =  '\n  Product           : ' + app;
  report += '\n  Path              : ' + mpsigstub_path;
  report += '\n  Installed version : ' + version;
  report += '\n  Fixed version     : ' + fix;
  report += '\n';

  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);

