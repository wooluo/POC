#
# 
#

include('compat.inc');

if (description)
{
  script_id(140792);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/25");

  script_cve_id("CVE-2020-16884");

  script_name(english:"Microsoft Edge (Chromium) < 85.0.564.44 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge (Chromium) installed on the remote Windows host is prior to 85.0.564.44. It is,
therefore, affected by a remote code execution vulnerability. The vulnerability exists in the way that the IEToEdge
Browser Helper Object (BHO) plugin on Internet Explorer handles objects in memory. An unauthenticated, remote attacker
can exploit this, by convincing a user to visit a specially crafted website designed to exploit this vulnerability, to
execute arbitrary code with the privileges of the current user. 

In order for the host to be vulnerable, it also must have Internet Explorer enabled, as only users that use Internet
Explorer to browse the internet are affected.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-16884
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7361a589");
  # https://docs.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ec7f076");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge (Chromium) 85.0.564.44 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16884");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated", "SMB/ARCH");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');
include('smb_hotfixes.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);

## Checking if IE is enabled

arch = get_kb_item_or_exit('SMB/ARCH');
path = NULL;
path_wow = NULL;

# Try to get App Paths. If not, defer to program files/Internet Explorer
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

key = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\IEXPLORE.EXE\\';
path = get_registry_value(handle:hklm, item:key);

if(isnull(path))
{
  path = hotfix_get_programfilesdir();
  path = hotfix_append_path(path:path, value:'Internet Explorer\\iexplore.exe');
}

if(arch == 'x64')
{

  key_wow = 'SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\IEXPLORE.EXE\\';
  path_wow = get_registry_value(handle:hklm, item:key);

  if(isnull(path_wow))
  {
    path_wow = hotfix_get_programfilesdirx86();
    path_wow = hotfix_append_path(path:path, value:'Internet Explorer\\iexplore.exe');
  }
}
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if(!isnull(path))
  ie_exists = hotfix_file_exists(path:path);
if(!isnull(path_wow))
  ie_exists_wow = hotfix_file_exists(path:path_wow);

hotfix_check_fversion_end();

if(!(ie_exists || ie_exists_wow))
{
  # IE is not enabled
  audit(AUDIT_HOST_NOT, 'affected. Microsoft Internet Explorer is not enabled');
}

constraints = [{ 'fixed_version' : '85.0.564.44' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
