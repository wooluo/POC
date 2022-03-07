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
  script_id(127853);
  script_version("1.3");
  script_cvs_date("Date: 2019/08/16 16:24:22");

  script_cve_id(
    "CVE-2019-1155",
    "CVE-2019-1199",
    "CVE-2019-1200",
    "CVE-2019-1201",
    "CVE-2019-1204",
    "CVE-2019-1205"
  );
  script_xref(name:"MSKB", value:"4475531");
  script_xref(name:"MSKB", value:"4475538");
  script_xref(name:"MSKB", value:"4475506");
  script_xref(name:"MSKB", value:"4464599");
  script_xref(name:"MSFT", value:"MS19-4475531");
  script_xref(name:"MSFT", value:"MS19-4475538");
  script_xref(name:"MSFT", value:"MS19-4475506");
  script_xref(name:"MSFT", value:"MS19-4464599");
  script_xref(name:"IAVA", value:"2019-A-0281");

  script_name(english:"Security Updates for Microsoft Office Products (August 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"A Microsoft Office product is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Outlook software when it fails to properly
    handle objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2019-1200)

  - A remote code execution vulnerability exists in
    Microsoft Outlook when the software fails to properly
    handle objects in memory. An attacker who successfully
    exploited the vulnerability could run arbitrary code in
    the context of the current user. If the current user is
    logged on with administrative user rights, an attacker
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2019-1199)

  - An elevation of privilege vulnerability exists when
    Microsoft Outlook initiates processing of incoming
    messages without sufficient validation of the formatting
    of the messages. An attacker who successfully exploited
    the vulnerability could attempt to force Outlook to load
    a local or remote message store (over SMB).
    (CVE-2019-1204)

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2019-1201,
    CVE-2019-1205)

  - A remote code execution vulnerability exists when the
    Windows Jet Database Engine improperly handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on a victim
    system. An attacker could exploit this vulnerability by
    enticing a victim to open a specially crafted file. The
    update addresses the vulnerability by correcting the way
    the Windows Jet Database Engine handles objects in
    memory. (CVE-2019-1155)");
  # https://support.microsoft.com/en-us/help/4475531/security-update-for-office-2010-august-13-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4475538/security-update-for-office-2016-august-13-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4475506/security-update-for-office-2010-august-13-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4464599/security-update-for-office-2013-august-13-2019
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4475531
  -KB4475538
  -KB4475506
  -KB4464599");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1155");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/13");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

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

bulletin = "MS19-08";
kbs = make_list(
  4464599,
  4475538,
  4475531,
  4475506
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

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

    path = hotfix_get_officeprogramfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office14');
    kb = "4475531";
    file = "wwlibcxm.dll";
    version = "14.0.7236.5000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office14');
    kb = "4475506";
    file = "aceexcl.dll";
    version = "14.0.7236.5000";
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
    kb = '4464599';
    file = "aceexcl.dll";
    version = "15.0.5163.1000";
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
    aceexcl_path = hotfix_append_path(path:path, value:"Microsoft Shared\Office16");

    path = hotfix_get_officecommonfilesdir(officever:"16.0");
    mso_dll_path = hotfix_append_path(path:path, value:"Microsoft Shared\Office16");

    c2r_path = mso_dll_path;

    # MSI aceexcl.dll
    if (hotfix_check_fversion(file:"aceexcl.dll", version:"16.0.4888.1000", channel:"MSI", channel_product:"Office", path:aceexcl_path, kb:'4475538', bulletin:bulletin, product:prod) == HCF_OLDER ||
      # C2R (csi path is the same as mso path)
      hotfix_check_fversion(file:"mso.dll", version:"16.0.9126.2432", channel:"Deferred", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:"mso.dll", version:"16.0.10730.20370", channel:"Deferred", channel_version:"1808", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:"mso.dll", version:"16.0.11328.20392", channel:"First Release for Deferred", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:"csi.dll", version:"16.0.11901.20218", channel:"Current", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      # 2019
      hotfix_check_fversion(file:"csi.dll", version:"16.0.11901.20218", channel:"2019 Retail", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod2019) == HCF_OLDER ||
      hotfix_check_fversion(file:"mso.dll", version:"16.0.10349.20017", channel:"2019 Volume", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod2019) == HCF_OLDER
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
