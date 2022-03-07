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
  script_id(125834);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/12  9:37:14");

  script_cve_id("CVE-2019-1029");
  script_bugtraq_id(108589);
  script_xref(name:"MSKB", value:"4506009");
  script_xref(name:"MSFT", value:"MS19-4506009");

  script_name(english:"Security Updates for Microsoft Lync Server and Skype for Business Server (June 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Lync Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Lync Server installation on the remote host is
missing a security update. It is, therefore, affected by the
following vulnerability :

  - A denial of service vulnerability exists in Microsoft
    Lync Server. An attacker who successfully exploited the
    vulnerability could cause Microsoft Lync Server to stop
    responding. Note that the denial of service would not
    allow an attacker to execute code or to elevate the
    attacker's user rights.  (CVE-2019-1029)");
  # https://support.microsoft.com/en-us/help/4506009/fix-for-lync-server-2013-and-lync-server-2010
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4506009 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include('install_func.inc');
include('datetime.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS19-06';
kbs = make_list('4506009');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, 'Failed to determine the location of %windir%.');

vuln = FALSE;
port = kb_smb_transport();

lync_installs = get_installs(app_name:'Microsoft Lync', exit_if_not_found:TRUE);

##
#
# Get full path of a dll in GAC_64
#
# @param file dll file name 
#
# @return full dir of the dll or NULL on error 
#
##
function get_dll_dir(file)
{
  local_var login, pass, domain;
  local_var dir, pat, share, subdir, ret;

  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();
  share = hotfix_get_systemdrive(as_share:TRUE);

  if(isnull(share)) return NULL;

  if(! smb_session_init()) return NULL;

  ret = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (ret != 1)
    return NULL; 
 
  # Microsoft.Rtc.Internal.Media.dll -> Microsoft.Rtc.Internal.Media  
  subdir= preg_replace(string:file, pattern:"([A-Za-z.]+).dll$", replace:"\1");

  dir = '\\Windows\\assembly\\GAC_64\\' + subdir + '\\';

  # subdir where Microsoft.Rtc.Internal.Media.dll is located:
  # 4.0.0.0__31bf3856ad364e35
  # v4.0_5.0.0.0__31bf3856ad364e35
  #
  ret = FindFirstFile(pattern:dir + '*_*');
  if(isnull(ret))
  {
    dir = '\\Windows\\Microsoft.NET\\assembly\\GAC_64\\' + subdir + '\\';
    ret = FindFirstFile(pattern:dir + '*_*');
  }

  if (isnull(ret))
  {
    NetUseDel(close:TRUE);
    return NULL;
  }

  subdir = ret[1];
 
  dir = dir + subdir + '\\'; 
  ret = FindFirstFile(pattern:dir + file);

  if (isnull(ret))
  {
    NetUseDel(close:TRUE);
    return NULL;
  }

  return (share[0] + ':' + dir);
}

file = 'Microsoft.Rtc.Internal.Media.dll';
path = get_dll_dir(file: file);
if(isnull(path))
  exit(1, 'Failed to determine the location of ' + file + '.');

foreach lync_install (lync_installs[1])
{
  if (lync_install['Product'] == 'Microsoft Lync Server 2010')
  {
    if (hotfix_check_fversion(file:file, version:'4.0.7577.766', min_version:'4.0.7577.0', path:path, bulletin:bulletin, kb:"4501056", product:"Microsoft Lync Server 2010") == HCF_OLDER)
      vuln = TRUE;
  }
  else if (lync_install['Product'] == 'Microsoft Lync Server 2013')
  {
    if (hotfix_check_fversion(file:file, version:'5.0.8308.1091', min_version:'5.0.8308.0', path:path, bulletin:bulletin, kb:"2809243", product:"Microsoft Lync Server 2013") == HCF_OLDER)
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
