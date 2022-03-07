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
  script_id(123952);
  script_version("1.5");
  script_cvs_date("Date: 2019/06/07 11:56:58");

  script_cve_id(
    "CVE-2019-0801",
    "CVE-2019-0822",
    "CVE-2019-0823",
    "CVE-2019-0824",
    "CVE-2019-0825",
    "CVE-2019-0826",
    "CVE-2019-0827",
    "CVE-2019-0828"
  );
  script_xref(name:"MSKB", value:"4462223");
  script_xref(name:"MSKB", value:"4464504");
  script_xref(name:"MSKB", value:"4462204");
  script_xref(name:"MSKB", value:"4464520");
  script_xref(name:"MSKB", value:"4462213");
  script_xref(name:"MSKB", value:"4462242");
  script_xref(name:"MSFT", value:"MS19-4462223");
  script_xref(name:"MSFT", value:"MS19-4464504");
  script_xref(name:"MSFT", value:"MS19-4462204");
  script_xref(name:"MSFT", value:"MS19-4464520");
  script_xref(name:"MSFT", value:"MS19-4462213");
  script_xref(name:"MSFT", value:"MS19-4462242");

  script_name(english:"Security Updates for Microsoft Office Products (April 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists when
    Microsoft Office fails to properly handle certain files.
    (CVE-2019-0801)

  - A remote code execution vulnerability exists in the way
    that Microsoft Graphics Components handle objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute arbitrary code on a target
    system.  (CVE-2019-0822)

  - A remote code execution vulnerability exists when the
    Microsoft Office Access Connectivity Engine improperly
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could execute arbitrary
    code on a victim system. An attacker could exploit this
    vulnerability by enticing a victim to open a specially
    crafted file. The update addresses the vulnerability by
    correcting the way the Microsoft Office Access
    Connectivity Engine handles objects in memory.
    (CVE-2019-0823, CVE-2019-0824, CVE-2019-0825,
    CVE-2019-0826, CVE-2019-0827)

  - A remote code execution vulnerability exists in
    Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2019-0828)");
  # https://support.microsoft.com/en-us/help/4462223/description-of-the-security-update-for-office-2010-april-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4464504/description-of-the-security-update-for-office-2013-april-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4462204/description-of-the-security-update-for-office-2013-april-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4464520/description-of-the-security-update-for-office-2010-april-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4462213/description-of-the-security-update-for-office-2016-april-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4462242/description-of-the-security-update-for-office-2016-april-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office365-proplus-by-date
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.office.com/en-us/article/install-office-updates-2ab296f3-7f03-43a2-8e50-46de917611c5
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4462223
  -KB4464504
  -KB4462204
  -KB4464520
  -KB4462213
  -KB4462242

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0801");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
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

global_var vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS19-04";
kbs = make_list(
  "4462204", # Office 2013
  "4462213", # Office 2016
  "4462223", # Office 2010
  "4462242", # Office 2016
  "4464504", # Office 2013
  "4464520"  # Office 2010
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

office_vers = hotfix_check_office_version();

# Office 2010 SP2
if (office_vers["14.0"])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (!isnull(office_sp) && office_sp == 2)
  {
    prod = "Microsoft Office 2010 SP2";

    path = hotfix_get_officecommonfilesdir(officever:"14.0");
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Office14");
    kb = "4462223";
    file = "mso.dll";
    version = "14.0.7232.5000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:"14.0");
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Office14");
    kb = "4464520";
    file = "acecore.dll";
    version = "14.0.7232.5000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
  }
}

# Office 2013 SP1
if (office_vers["15.0"])
{
  office_sp = get_kb_item("SMB/Office/2013/SP");
  if (!isnull(office_sp) && office_sp == 1)
  {
    prod = "Microsoft Office 2013 SP1";

    path = hotfix_get_officecommonfilesdir(officever:"15.0");
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Office15");
    kb = "4464504";
    file = "mso.dll";
    version = "15.0.5127.1000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:"15.0");
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Office15");
    kb = "4462204";
    file = "acecore.dll";
    version = "15.0.5125.1000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
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

    path = hotfix_get_officecommonfilesdir(officever:"16.0");
    acecore_dll_path = hotfix_append_path(path:path, value:"Microsoft Shared\Office16");

    c2r_path = mso_dll_path;

    # MSI acecore.dll
    if (hotfix_check_fversion(file:"acecore.dll", version:"16.0.4831.1000", channel:"MSI", channel_product:"Office", path:acecore_dll_path, kb:"4462213", bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    if (
      # MSI mso.dll
      hotfix_check_fversion(file:"mso.dll", version:"16.0.4834.1000", channel:"MSI", channel_product:"Office", path:mso_dll_path, kb:"4462242", bulletin:bulletin, product:prod) == HCF_OLDER ||
      # C2R
      hotfix_check_fversion(file:"mso.dll", version:"16.0.9126.2382", channel:"Deferred", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:"mso.dll", version:"16.0.10730.20334", channel:"Deferred", channel_version:"1808", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:"mso.dll", version:"16.0.11328.20230", channel:"First Release for Deferred", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:"mso.dll", version:"16.0.11425.20204", channel:"Current", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      # 2019
      hotfix_check_fversion(file:"mso.dll", version:"16.0.11425.20204", channel:"2019 Retail", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod2019) == HCF_OLDER ||
      hotfix_check_fversion(file:"mso.dll", version:"16.0.10343.20013", channel:"2019 Volume", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod2019) == HCF_OLDER
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
