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
  script_id(121025);
  script_version("1.6");
  script_cvs_date("Date: 2019/04/30 14:30:16");

  script_cve_id(
    "CVE-2019-0541",
    "CVE-2019-0585"
  );
  script_xref(name:"MSKB", value:"4461635");
  script_xref(name:"MSKB", value:"4462112");
  script_xref(name:"MSKB", value:"2596760");
  script_xref(name:"MSFT", value:"MS19-4461635");
  script_xref(name:"MSFT", value:"MS19-4462112");
  script_xref(name:"MSFT", value:"MS19-2596760");

  script_name(english:"Security Updates for Microsoft Office Viewer Products (January 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Viewer Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Viewer Products are missing security
updates. It is, therefore, affected by multiple
vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2019-0585)

  - A remote code execution vulnerability exists in the way
    that the MSHTML engine inproperly validates input. An
    attacker could execute arbitrary code in the context of
    the current user.  (CVE-2019-0541)");
  # https://support.microsoft.com/en-us/help/4461635/description-of-the-security-update-for-word-viewer-january-8-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4462112/description-of-the-security-update-for-word-viewer-january-8-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/2596760/description-of-the-security-update-for-excel-viewer-2007-january
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4461635
  -KB4462112
  -KB2596760");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0541");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl","microsoft_office_compatibility_pack_installed.nbin","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
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

bulletin = "MS19-01";
kbs = make_list(
  '2596760', # Excel Viewer 2007
  '4461635', # Word Viewer
  '4462112'  # Word Viewer
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Excel Viewer
######################################################################
function perform_excel_viewer_checks()
{
  var prod_exel, path, install, installs, common_path;
  prod_exel = "Microsoft Excel Viewer";
  installs = get_kb_list("SMB/Office/ExcelViewer/*/ProductPath");

  foreach install (keys(installs))
  {
    common_path = installs[install];
    path = ereg_replace(pattern:"^([A-Za-z]:.*)\\Microsoft Office.*", replace:"\1\Microsoft Office\Office12", string:common_path);

    if (hotfix_check_fversion(file:"msohev.dll", version:"12.0.6806.5000", path:path, kb:"2596760", product:prod_exel) == HCF_OLDER) vuln = TRUE;
  }
}

######################################################################
# Word Viewer
######################################################################
function perform_word_viewer_checks()
{
  var install, installs, path, prod;
  prod = "Microsoft Word Viewer";

  installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
  foreach install (keys(installs))
  {
    path = installs[install];
    path = ereg_replace(pattern:"^([A-Za-z]:.*)\\[wW]ordview.exe", replace:"\1", string:path);

    if (hotfix_check_fversion(file:"msohtmed.exe", version:"11.0.8453.0", path:path, kb:"4461635", product:prod) == HCF_OLDER)
      vuln = TRUE;

    if (hotfix_check_fversion(file:"Wordview.exe", version:"11.0.8454.0", path:path, kb:"4462112", product:prod) == HCF_OLDER)
      vuln = TRUE;
  }
}


######################################################################
# MAIN
######################################################################
perform_excel_viewer_checks();
perform_word_viewer_checks();

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
