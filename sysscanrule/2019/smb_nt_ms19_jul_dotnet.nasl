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
  script_id(126600);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/15 11:09:49");

  script_cve_id(
    "CVE-2019-1006",
    "CVE-2019-1083",
    "CVE-2019-1113"
  );
  script_bugtraq_id(
    108977,
    108981
  );
  script_xref(name:"MSKB", value:"4507435");
  script_xref(name:"MSKB", value:"4507460");
  script_xref(name:"MSKB", value:"4507423");
  script_xref(name:"MSKB", value:"4507422");
  script_xref(name:"MSKB", value:"4507421");
  script_xref(name:"MSKB", value:"4507420");
  script_xref(name:"MSKB", value:"4507414");
  script_xref(name:"MSKB", value:"4507419");
  script_xref(name:"MSKB", value:"4507412");
  script_xref(name:"MSKB", value:"4507413");
  script_xref(name:"MSKB", value:"4507411");
  script_xref(name:"MSKB", value:"4506991");
  script_xref(name:"MSKB", value:"4507450");
  script_xref(name:"MSKB", value:"4506987");
  script_xref(name:"MSKB", value:"4506986");
  script_xref(name:"MSKB", value:"4507455");
  script_xref(name:"MSKB", value:"4506989");
  script_xref(name:"MSKB", value:"4506988");
  script_xref(name:"MSKB", value:"4507458");
  script_xref(name:"MSFT", value:"MS19-4507435");
  script_xref(name:"MSFT", value:"MS19-4507460");
  script_xref(name:"MSFT", value:"MS19-4507423");
  script_xref(name:"MSFT", value:"MS19-4507422");
  script_xref(name:"MSFT", value:"MS19-4507421");
  script_xref(name:"MSFT", value:"MS19-4507420");
  script_xref(name:"MSFT", value:"MS19-4507414");
  script_xref(name:"MSFT", value:"MS19-4507419");
  script_xref(name:"MSFT", value:"MS19-4507412");
  script_xref(name:"MSFT", value:"MS19-4507413");
  script_xref(name:"MSFT", value:"MS19-4507411");
  script_xref(name:"MSFT", value:"MS19-4506991");
  script_xref(name:"MSFT", value:"MS19-4507450");
  script_xref(name:"MSFT", value:"MS19-4506987");
  script_xref(name:"MSFT", value:"MS19-4506986");
  script_xref(name:"MSFT", value:"MS19-4507455");
  script_xref(name:"MSFT", value:"MS19-4506989");
  script_xref(name:"MSFT", value:"MS19-4506988");
  script_xref(name:"MSFT", value:"MS19-4507458");
  script_xref(name:"IAVA", value:"2019-A-0240");

  script_name(english:"Security Updates for Microsoft .NET Framework (July 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - An authentication bypass vulnerability exists in Windows
    Communication Foundation (WCF) and Windows Identity
    Foundation (WIF), allowing signing of SAML tokens with
    arbitrary symmetric keys. This vulnerability allows an
    attacker to impersonate another user, which can lead to
    elevation of privileges. The vulnerability exists in
    WCF, WIF 3.5 and above in .NET Framework, WIF 1.0
    component in Windows, WIF Nuget package, and WIF
    implementation in SharePoint. An unauthenticated
    attacker can exploit this by signing a SAML token with
    any arbitrary symmetric key. This security update
    addresses the issue by ensuring all versions of WCF and
    WIF validate the key used to sign SAML tokens correctly.
    (CVE-2019-1006)

  - A remote code execution vulnerability exists in .NET
    software when the software fails to check the source
    markup of a file. An attacker who successfully exploited
    the vulnerability could run arbitrary code in the
    context of the current user. If the current user is
    logged on with administrative user rights, an attacker
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2019-1113)

  - A denial of service vulnerability exists when Microsoft
    Common Object Runtime Library improperly handles web
    requests. An attacker who successfully exploited this
    vulnerability could cause a denial of service against a
    .NET web application. A remote unauthenticated attacker
    could exploit this vulnerability by issuing specially
    crafted requests to the .NET application. The update
    addresses the vulnerability by correcting how the .NET
    web application handles web requests. (CVE-2019-1083)");
  # https://support.microsoft.com/en-us/help/4507435/windows-10-update-kb4507435
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4507460/windows-10-update-kb4507460
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4507423/security-and-quality-rollup-for-net-framework-2-0-3-0-4-5-2-4-6
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4507422/security-and-quality-rollup-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4507421/security-and-quality-rollup-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4507420/security-and-quality-rollup-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4507414/security-only-update-for-net-framework-3-0-sp2-4-5-2-4-6
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4507419/july-9-2019-kb4507419-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4507412/security-only-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4507413/security-only-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4507411/security-only-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4506991/july-9-2019-kb4506991-cumulative-update-for-net-framework-3-5-and-4-8
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4507450/windows-10-update-kb4507450
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4506987/july-9-2019-kb4506987-cumulative-update-for-net-framework-4-8
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4506986/july-9-2019-kb4506986-cumulative-update-for-net-framework-4-8
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4507455/windows-10-update-kb4507455
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4506989/july-9-2019-kb4506989-cumulative-update-for-net-framework-4-8
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4506988/july-9-2019-kb4506988-cumulative-update-for-net-framework-4-8
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4507458/windows-10-update-kb4507458
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1113");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_dotnet_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_net_framework_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}
include('audit.inc');
include('global_settings.inc');
include('install_func.inc');
include('misc_func.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS19-07';
kbs = make_list(
  '4506986',
  '4506987',
  '4506988',
  '4506989',
  '4506991',
  '4507411',
  '4507412',
  '4507413',
  '4507414',
  '4507419',
  '4507420',
  '4507421',
  '4507422',
  '4507423',
  '4507435',
  '4507450',
  '4507455',
  '4507458',
  '4507460'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit('SMB/ProductName', exit_code:1);
if ('Windows 8' >< productname && 'Windows 8.1' >!< productname) audit(AUDIT_OS_SP_NOT_VULN);
else if ('Vista' >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

app = 'Microsoft .NET Framework';
get_install_count(app_name:app, exit_if_zero:TRUE);
installs = get_combined_installs(app_name:app);

vuln = 0;

if (installs[0] == 0)
{
  foreach install (installs[1])
  {
    version = install['version'];
    if( version != UNKNOWN_VER &&
        smb_check_dotnet_rollup(rollup_date:'07_2019', dotnet_ver:version))
      vuln++;
  }
}
if(vuln)
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

