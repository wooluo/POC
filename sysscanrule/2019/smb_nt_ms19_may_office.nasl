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
  script_id(125071);
  script_version("1.7");
  script_cvs_date("Date: 2019/07/01 13:01:35");

  script_cve_id(
    "CVE-2019-0945",
    "CVE-2019-0946",
    "CVE-2019-0947"
  );
  script_xref(name:"MSKB", value:"4464567");
  script_xref(name:"MSKB", value:"4464551");
  script_xref(name:"MSKB", value:"4464561");
  script_xref(name:"MSFT", value:"MS19-4464567");
  script_xref(name:"MSFT", value:"MS19-4464551");
  script_xref(name:"MSFT", value:"MS19-4464561");

  script_name(english:"Security Updates for Microsoft Office Products (May 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. It is, therefore, affected by multiple remote code execution
vulnerabilities due to the way Microsoft Office Access Connectivity Engine improperly handles objects in memory. An
attacker who successfully exploited these vulnerabilities could execute arbitrary code on a victim system. An attacker
could exploit these vulnerabilities by enticing a victim to open a specially crafted file. The update addresses the
vulnerabilities by correcting the way the Microsoft Office Access Connectivity Engine handles objects in memory.");
  # https://support.microsoft.com/en-us/help/4464567/description-of-the-security-update-for-office-2010-may-14-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4464551/description-of-the-security-update-for-office-2016-may-14-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4464561/description-of-the-security-update-for-office-2013-may-14-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office365-proplus-by-date
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.office.com/en-us/article/install-office-updates-2ab296f3-7f03-43a2-8e50-46de917611c5
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4464567
  -KB4464551
  -KB4464561

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0945");
  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Windows : Microsoft Bulletins");

  script_dependencies("office_installed.nasl","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
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

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS19-05';
kbs = make_list(
  '4464567', # Office 2010 SP2
  '4464561', # Office 2013 SP1
  '4464551'  # Office 2016
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

office_vers = hotfix_check_office_version();

# Office 2010 SP2
if (office_vers['14.0'])
{
  office_sp = get_kb_item('SMB/Office/2010/SP');
  if (!isnull(office_sp) && office_sp == 2)
  {
    prod = 'Microsoft Office 2010 SP2';

    path = hotfix_get_officecommonfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office14');
    kb = '4464567';
    file = "aceexcl.dll";
    version = "14.0.7233.5000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
  }
}

# Office 2013 SP1
if (office_vers['15.0'])
{
  office_sp = get_kb_item('SMB/Office/2013/SP');
  if (!isnull(office_sp) && office_sp == 1)
  {
    prod = 'Microsoft Office 2013 SP1';

    path = hotfix_get_officecommonfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office15');
    kb = '4464561';
    file = "aceexcl.dll";
    version = "15.0.5137.1000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;
  }
}

# Office 2016
if (office_vers["16.0"])
{
  office_sp = get_kb_item("SMB/Office/2016/SP");
  if (!isnull(office_sp) && office_sp == 0)
  {
    prod = "Microsoft Office 2016";
    prod2019 = "Microsoft Office 2019";

    path = hotfix_get_officecommonfilesdir(officever:"16.0");
    mso_dll_path = hotfix_append_path(path:path, value:"Microsoft Shared\Office16");

    c2r_path = mso_dll_path;

    # MSI acecore.dll
    if (
      hotfix_check_fversion(file:"aceexcl.dll", version:"16.0.4849.1000", channel:"MSI", channel_product:"Office", path:mso_dll_path, kb:"4464551", bulletin:bulletin, product:prod) == HCF_OLDER ||
      # C2R
      hotfix_check_fversion(file:"mso.dll", version:"16.0.9126.2387", channel:"Deferred", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:"mso.dll", version:"16.0.10730.20344", channel:"Deferred", channel_version:"1808", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:"mso.dll", version:"16.0.11328.20286", channel:"First Release for Deferred", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:"mso.dll", version:"16.0.11601.20204", channel:"Current", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      # 2019
      hotfix_check_fversion(file:"mso.dll", version:"16.0.11601.20204", channel:"2019 Retail", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod2019) == HCF_OLDER ||
      hotfix_check_fversion(file:"mso.dll", version:"16.0.10344.20008", channel:"2019 Volume", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod2019) == HCF_OLDER
    )
    vuln = TRUE;
  }
}

if (vuln)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
