#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
include("compat.inc");

if (description)
{
  script_id(122869);
  script_version("1.3");
  script_cvs_date("Date: 2019/05/03 15:02:32");

  script_cve_id("CVE-2019-0798");
  script_xref(name:"MSKB", value:"4492302");
  script_xref(name:"MSKB", value:"4492303");
  script_xref(name:"MSFT", value:"MS19-4492302");
  script_xref(name:"MSFT", value:"MS19-4492303");
  script_xref(name:"IAVA", value:"2019-A-0076");

  script_name(english:"Skype for Business and Lync Spoofing Vulnerability");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
  "The Microsoft Skype for Business or Microsoft Lync installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Skype for Business or Microsoft Lync installation on
the remote host is missing a security update. It is, therefore,
affected by the following vulnerability :

  - A spoofing vulnerability exists when a Skype for Business
    2015 server does not properly sanitize a specially
    crafted request. An authenticated attacker could exploit
    the vulnerability by sending a specially crafted request
    to an affected Skype for Business server. The attacker
    who successfully exploited this vulnerability could then
    perform cross-site scripting attacks on affected systems
    and run script in the security context of the current
    user. (CVE-2019-0798)");
  # https://support.microsoft.com/en-us/help/3061064/updates-for-skype-for-business-server-2015
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4492302
  -KB4492303");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0798");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/15");
  script_set_attribute(attribute:"stig_severity", value:"I");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl","microsoft_lync_server_installed.nasl","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");
include("datetime.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS19-03";
kbs = make_list(
  '4492302', # Skype for Business Server 2015, Web Application
  '4492303', # Skype for Business Server 2015, Update For Core Components
  '4494279'  # Lync Server 2013 spoofing vulnerability

);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");

vuln = FALSE;
port = kb_smb_transport();

lync_installs = get_installs(app_name:"Microsoft Lync", exit_if_not_found:TRUE);

function get_last_modified_time(file)
{
  local_var login  = kb_smb_login();
  local_var pass   = kb_smb_password();
  local_var domain = kb_smb_domain();
  local_var share = preg_replace(string:file, pattern:"^([A-Za-z]):.*", replace:"\1$");
  local_var path = preg_replace(string:file, pattern:"^[A-Za-z]:(.*)", replace:"\1");

  if ( hcf_init == 0 ) hotfix_check_fversion_init();
  local_var r = NetUseAdd(login:login, password:pass, domain:domain, share:share);

  local_var ret = FindFirstFile(pattern:path);

  NetUseDel(close:FALSE);

  if (isnull(ret))
    return NULL;

  # ftLastWriteTime
  return ret[3][2];
}

foreach lync_install (lync_installs[1])
{
  # Skype for Business Server 2015
  if (lync_install["Product"] == "Skype for Business Server 2015")
  {
    file = hotfix_append_path(path:lync_install["path"], value:"Web Components\LWA\Ext\Scripts\UI\Lync.Client.MiscClientConsolidated.js");
    if (!hotfix_file_exists(path:file)) continue;
    timestamp = get_last_modified_time(file:file);
    # Feb. 26, 2019 at 03:41:58 GMT
    patched_timestamp = 1551152518;

    if (isnull(timestamp) || timestamp < patched_timestamp)
    {
      vuln = TRUE;
      kb = "4492303";
      if (isnull(timestamp)) display_timestamp = "(none)";
      else display_timestamp = strftime(timestamp);
      info =
        '\n  Product             : Skype for Business Server 2015' +
        '\n  File                : ' + path +
        '\n  Installed timestamp : ' + display_timestamp +
        '\n  Fixed timestamp     : ' + strftime(patched_timestamp) +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }
  }
  else if (lync_install["Product"] == "Microsoft Lync Server 2013")
  {
    path = hotfix_append_path(path:lync_install["path"], value:"Server\Core");
    if (hotfix_check_fversion(file:"InterClusterRouting.exe", version:"5.0.8308.1068", min_version:"5.0.8308.0", path:path, bulletin:bulletin, kb:"4494279", product:"Microsoft Lync Server 2013") == HCF_OLDER)
      vuln = TRUE;
  }
}

if (vuln)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
