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
  script_id(126628);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/11 18:07:39");

  script_cve_id("CVE-2019-1084");
  script_xref(name:"MSKB", value:"4475545");
  script_xref(name:"MSKB", value:"4475519");
  script_xref(name:"MSFT", value:"MS19-4475545");
  script_xref(name:"MSFT", value:"MS19-4475519");
  script_xref(name:"IAVA", value:"2019-A-0233");

  script_name(english:"Security Updates for Microsoft Skype for Business and Microsoft Lync (July 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
  "The Microsoft Skype for Business or Microsoft Lync installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
  "The Microsoft Skype for Business or Microsoft Lync
installation on the remote host is missing a security
update. It is, therefore, affected by the following
vulnerability :

  - An information disclosure vulnerability exists when
    Exchange allows creation of entities with Display Names
    having non-printable characters. An authenticated
    attacker could exploit this vulnerability by creating
    entities with invalid display names, which, when added
    to conversations, remain invisible. This security update
    addresses the issue by validating display names upon
    creation in Microsoft Exchange, and by rendering invalid
    display names correctly in Microsoft Outlook clients.
    (CVE-2019-1084)");

  # https://support.microsoft.com/en-us/help/4475545/security-update-for-skype-for-business-2016-july-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4475519/security-update-for-skype-for-business-2015-lync-2013
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
  "Microsoft has released the following security updates to address this issue:  
      -KB4475545
      -KB4475519");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1084");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
include("obj.inc");

global_var vuln;

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = "MS19-03";
kbs = make_list(
  '4475545', # Skype for Business 2016
  '4475519'  # Skype for Business 2015 (Lync 2013)
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, 'Failed to determine the location of %windir%.');

vuln = FALSE;
port = kb_smb_transport();

function perform_skype_checks()
{
  if (int(get_install_count(app_name:"Microsoft Lync")) <= 0)
    return NULL;

  var lync_install, lync_installs, kb, file, prod;
  var found, report, uninstall_key, uninstall_keys;

  lync_installs = get_installs(app_name:"Microsoft Lync");

  foreach lync_install (lync_installs[1])
  {
    if (
      lync_install["version"] =~ "^16\.0\." &&
      "Server" >!< lync_install["Product"]
    )
    {
      file = "Lync.exe";
      prod = "Microsoft Lync";
      kb = "4475545";

      if (hotfix_check_fversion(file:file, version:"16.0.4873.1001", path:lync_install["path"], bulletin:bulletin, kb:kb, product:prod) == HCF_OLDER)
          vuln = TRUE;
    }
    else if (
      lync_install["version"] =~ "^15\.0\." &&
      "Server" >!< lync_install["Product"]
    )
    {
      file = "Lync.exe";
      prod = "Microsoft Lync";
      kb = "4475519";

      if (hotfix_check_fversion(file:file, version:"15.0.5153.1001", path:lync_install["path"], bulletin:bulletin, kb:kb, product:prod) == HCF_OLDER)
          vuln = TRUE;
    }
  }
}
perform_skype_checks();

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