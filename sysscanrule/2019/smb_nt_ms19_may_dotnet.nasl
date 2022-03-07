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
  script_id(125074);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/12 12:39:17");

  script_cve_id(
    "CVE-2019-0820",
    "CVE-2019-0864",
    "CVE-2019-0980",
    "CVE-2019-0981"
  );
  script_bugtraq_id(
    108207,
    108232,
    108241,
    108245
  );
  script_xref(name:"MSKB", value:"4499179");
  script_xref(name:"MSKB", value:"4494440");
  script_xref(name:"MSKB", value:"4499406");
  script_xref(name:"MSKB", value:"4499409");
  script_xref(name:"MSKB", value:"4499408");
  script_xref(name:"MSKB", value:"4495611");
  script_xref(name:"MSKB", value:"4499405");
  script_xref(name:"MSKB", value:"4499407");
  script_xref(name:"MSKB", value:"4499154");
  script_xref(name:"MSKB", value:"4495610");
  script_xref(name:"MSKB", value:"4499167");
  script_xref(name:"MSKB", value:"4495613");
  script_xref(name:"MSKB", value:"4495616");
  script_xref(name:"MSKB", value:"4499181");
  script_xref(name:"MSKB", value:"4498964");
  script_xref(name:"MSKB", value:"4498961");
  script_xref(name:"MSKB", value:"4495620");
  script_xref(name:"MSKB", value:"4498963");
  script_xref(name:"MSKB", value:"4498962");
  script_xref(name:"MSFT", value:"MS19-4499179");
  script_xref(name:"MSFT", value:"MS19-4494440");
  script_xref(name:"MSFT", value:"MS19-4499406");
  script_xref(name:"MSFT", value:"MS19-4499409");
  script_xref(name:"MSFT", value:"MS19-4499408");
  script_xref(name:"MSFT", value:"MS19-4495611");
  script_xref(name:"MSFT", value:"MS19-4499405");
  script_xref(name:"MSFT", value:"MS19-4499407");
  script_xref(name:"MSFT", value:"MS19-4499154");
  script_xref(name:"MSFT", value:"MS19-4495610");
  script_xref(name:"MSFT", value:"MS19-4499167");
  script_xref(name:"MSFT", value:"MS19-4495613");
  script_xref(name:"MSFT", value:"MS19-4495616");
  script_xref(name:"MSFT", value:"MS19-4499181");
  script_xref(name:"MSFT", value:"MS19-4498964");
  script_xref(name:"MSFT", value:"MS19-4498961");
  script_xref(name:"MSFT", value:"MS19-4495620");
  script_xref(name:"MSFT", value:"MS19-4498963");
  script_xref(name:"MSFT", value:"MS19-4498962");

  script_name(english:"Security Updates for Microsoft .NET Framework (May 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A denial of service vulnerability exists when .NET
    Framework improperly handles objects in heap memory. An
    attacker who successfully exploited this vulnerability
    could cause a denial of service against a .NET
    application.  (CVE-2019-0864)

  - A denial of service vulnerability exists when .NET
    Framework and .NET Core improperly process RegEx
    strings. An attacker who successfully exploited this
    vulnerability could cause a denial of service against a
    .NET application. A remote unauthenticated attacker
    could exploit this vulnerability by issuing specially
    crafted requests to a .NET Framework (or .NET core)
    application. The update addresses the vulnerability by
    correcting how .NET Framework and .NET Core applications
    handle RegEx string processing. (CVE-2019-0820)

  - A denial of service vulnerability exists when .NET
    Framework or .NET Core improperly handle web requests.
    An attacker who successfully exploited this
    vulnerability could cause a denial of service against a
    .NET Framework or .NET Core web application. The
    vulnerability can be exploited remotely, without
    authentication. A remote unauthenticated attacker could
    exploit this vulnerability by issuing specially crafted
    requests to the .NET Framework or .NET Core application.
    The update addresses the vulnerability by correcting how
    .NET Framework or .NET Core web applications handles web
    requests. (CVE-2019-0980, CVE-2019-0981)");
  # https://support.microsoft.com/en-us/help/4499179/windows-10-update-kb4499179
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4494440/windows-10-update-kb4494440
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4499406/security-and-quality-rollup-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4499409/security-and-quality-rollup-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4499408/security-and-quality-rollup-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4495611/may-14-2019-kb4495611-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4499405/may-14-2019-kb4499405-cumulative-update-for-net-framework-3-5-4-7-2-an
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4499407/security-and-quality-rollup-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4499154/windows-10-update-kb4499154
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4495610/may-14-2019-kb4495610-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4499167/windows-10-update-kb4499167
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4495613/may-14-2019-kb4495613-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4495616/may-14-2019-kb4495616-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4499181/windows-10-update-kb4499181
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4498964/security-only-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4498961/security-only-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4495620/may-14-2019-kb4495620-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4498963/security-only-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4498962/security-only-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0820");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/15");

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

include('audit.inc');
include('global_settings.inc');
include('install_func.inc');
include('misc_func.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS19-05';
kbs = make_list(
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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
        smb_check_dotnet_rollup(rollup_date:'05_2019', dotnet_ver:version))
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
  audit(AUDIT_HOST_NOT, 'affected');
} 
