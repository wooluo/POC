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
  script_id(121021);
  script_version("1.4");
  script_cvs_date("Date: 2019/02/14 17:26:20");

  script_cve_id("CVE-2019-0545");
  script_xref(name:"MSKB", value:"4480051");
  script_xref(name:"MSKB", value:"4480054");
  script_xref(name:"MSKB", value:"4480055");
  script_xref(name:"MSKB", value:"4480056");
  script_xref(name:"MSKB", value:"4480057");
  script_xref(name:"MSKB", value:"4480058");
  script_xref(name:"MSKB", value:"4480059");
  script_xref(name:"MSKB", value:"4480061");
  script_xref(name:"MSKB", value:"4480062");
  script_xref(name:"MSKB", value:"4480063");
  script_xref(name:"MSKB", value:"4480064");
  script_xref(name:"MSKB", value:"4480070");
  script_xref(name:"MSKB", value:"4480071");
  script_xref(name:"MSKB", value:"4480072");
  script_xref(name:"MSKB", value:"4480074");
  script_xref(name:"MSKB", value:"4480075");
  script_xref(name:"MSKB", value:"4480076");
  script_xref(name:"MSKB", value:"4480083");
  script_xref(name:"MSKB", value:"4480084");
  script_xref(name:"MSKB", value:"4480085");
  script_xref(name:"MSKB", value:"4480086");
  script_xref(name:"MSKB", value:"4480961");
  script_xref(name:"MSKB", value:"4480962");
  script_xref(name:"MSKB", value:"4480966");
  script_xref(name:"MSKB", value:"4480973");
  script_xref(name:"MSKB", value:"4480978");
  script_xref(name:"MSFT", value:"MS19-4480051");
  script_xref(name:"MSFT", value:"MS19-4480054");
  script_xref(name:"MSFT", value:"MS19-4480055");
  script_xref(name:"MSFT", value:"MS19-4480056");
  script_xref(name:"MSFT", value:"MS19-4480057");
  script_xref(name:"MSFT", value:"MS19-4480058");
  script_xref(name:"MSFT", value:"MS19-4480059");
  script_xref(name:"MSFT", value:"MS19-4480061");
  script_xref(name:"MSFT", value:"MS19-4480062");
  script_xref(name:"MSFT", value:"MS19-4480063");
  script_xref(name:"MSFT", value:"MS19-4480064");
  script_xref(name:"MSFT", value:"MS19-4480070");
  script_xref(name:"MSFT", value:"MS19-4480071");
  script_xref(name:"MSFT", value:"MS19-4480072");
  script_xref(name:"MSFT", value:"MS19-4480074");
  script_xref(name:"MSFT", value:"MS19-4480075");
  script_xref(name:"MSFT", value:"MS19-4480076");
  script_xref(name:"MSFT", value:"MS19-4480083");
  script_xref(name:"MSFT", value:"MS19-4480084");
  script_xref(name:"MSFT", value:"MS19-4480085");
  script_xref(name:"MSFT", value:"MS19-4480086");
  script_xref(name:"MSFT", value:"MS19-4480961");
  script_xref(name:"MSFT", value:"MS19-4480962");
  script_xref(name:"MSFT", value:"MS19-4480966");
  script_xref(name:"MSFT", value:"MS19-4480973");
  script_xref(name:"MSFT", value:"MS19-4480978");

  script_name(english:"Security Updates for Microsoft .NET Framework (January 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is
missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host
is missing a security update. It is, therefore, affected by
the following vulnerability :

  - An information disclosure vulnerability exists in .NET
    Framework and .NET Core which allows bypassing Cross-
    origin Resource Sharing (CORS) configurations. An
    attacker who successfully exploited the vulnerability
    could retrieve content, that is normally restricted,
    from a web application. The security update addresses
    the vulnerability by enforcing CORS configuration to
    prevent its bypass. (CVE-2019-0545)");
  # https://support.microsoft.com/en-us/help/4480961/windows-10-update-kb4480961
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480962/windows-10-update-kb4480962
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480966/windows-10-update-kb4480966
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480072/description-of-security-only-update-for-net-framework-4-6-to-4-7-2
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480070/description-of-security-only-update-for-net-framework-4-6-to-4-7-2
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480071/description-of-security-only-update-for-net-framework-4-6-to-4-7-2
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480076/description-of-security-only-update-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480074/description-of-security-only-update-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480075/description-of-security-only-update-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480058/description-of-security-and-quality-rollup-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480059/description-of-security-and-quality-rollup-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480051/description-security-and-quality-rollup-for-net-framework-4-6-to-4-7-2
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480054/description-security-and-quality-rollup-for-net-framework-4-6-to-4-7-2
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480055/description-of-security-and-quality-rollup-for-net-framework-4-6
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480056/january-8-2018-kb4480056
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480057/description-of-security-and-quality-rollup-for-net-framework-4-5-2
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480973/windows-10-update-kb4480973
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480978/windows-10-update-kb4480978
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480064/description-of-security-and-quality-rollup-for-net-framework-3-5
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480061/description-of-security-and-quality-rollup-for-net-framework-3-5
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480063/description-of-security-and-quality-rollup-for-net-framework-3-5-1
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480062/description-of-security-and-quality-rollup-for-net-framework-2-0-and-3
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480086/description-of-security-only-update-for-net-framework-3-5
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480085/description-of-security-only-update-for-net-framework-3-5-1
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480084/description-of-security-only-update-for-net-framework-2-0-and-3-0
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4480083/description-of-security-only-update-for-net-framework-3-5
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0545");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_dotnet_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_net_framework_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = "MS19-01";
kbs = make_list(
  "4480051",
  "4480054",
  "4480055",
  "4480056",
  "4480057",
  "4480058",
  "4480059",
  "4480061",
  "4480062",
  "4480063",
  "4480064",
  "4480070",
  "4480071",
  "4480072",
  "4480074",
  "4480075",
  "4480076",
  "4480083",
  "4480084",
  "4480085",
  "4480086",
  "4480961",
  "4480962",
  "4480966",
  "4480973",
  "4480978"
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);
else if ("Vista" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

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
        smb_check_dotnet_rollup(rollup_date:"01_2019", dotnet_ver:version))
      vuln++;
  }
}
if(vuln)
{
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, "affected");
} 
