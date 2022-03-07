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
  script_id(121213);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/26  4:50:09");

  script_cve_id("CVE-2019-0624");
  script_xref(name:"MSKB", value:"3061064");
  script_xref(name:"MSKB", value:"4464359");
  script_xref(name:"MSKB", value:"4464354");
  script_xref(name:"MSKB", value:"4464355");
  script_xref(name:"MSKB", value:"4464358");
  script_xref(name:"MSKB", value:"4464356");
  script_xref(name:"MSKB", value:"4464360");
  script_xref(name:"MSKB", value:"4464357");
  script_xref(name:"MSFT", value:"MS19-3061064");
  script_xref(name:"MSFT", value:"MS19-4464359");
  script_xref(name:"MSFT", value:"MS19-4464354");
  script_xref(name:"MSFT", value:"MS19-4464355");
  script_xref(name:"MSFT", value:"MS19-4464358");
  script_xref(name:"MSFT", value:"MS19-4464356");
  script_xref(name:"MSFT", value:"MS19-4464360");
  script_xref(name:"MSFT", value:"MS19-4464357");

  script_name(english:"Security Updates for Microsoft Skype for Business and Microsoft Lync (January 2019 OOB)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
  "The Microsoft Skype for Business or Microsoft Lync installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Skype for Business or Microsoft Lync
installation on the remote host is missing a security
update. It is, therefore, affected by the following
vulnerability :

  - A spoofing vulnerability exists when a Skype for Business 2015
    server does not properly sanitize a specially crafted request. An
    authenticated attacker could exploit the vulnerability by sending
    a specially crafted request to an affected Skype for Business
    server. The attacker who successfully exploited this
    vulnerability could then perform cross-site scripting attacks on
    affected systems and run script in the security context of the
    current user. (CVE-2019-0624)");
  # https://support.microsoft.com/en-us/help/3061064/updates-for-skype-for-business-server-2015
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB3061064
  -KB4464359
  -KB4464354
  -KB4464355
  -KB4464358
  -KB4464356
  -KB4464360
  -KB4464357");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0624");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/16");

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

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS19-01";
kbs = make_list(
  '3061064', # Skype for Business 2015 Cumulative Server Update Installer
  '4464359', # Skype for Business Server 2015, Web Components Server 
  '4464354', # Skype for Business Server 2015, Core Components
  '4464355', # Skype for Business Server 2015, Front End Server and Edge Server
  '4464358', # Skype for Business Server 2015, Mediation Server
  '4464356', # Skype for Business Server 2015, Response Group Service
  '4464360', # Skype for Business Server 2015 and Unified Communications Managed API 5.0 Runtime
  '4464357'  # Skype for Business Server 2015, Conferencing Server
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");

vuln = FALSE;
port = kb_smb_transport();

lync_installs = get_installs(app_name:"Microsoft Lync", exit_if_not_found:TRUE);

foreach lync_install (lync_installs[1])
{
  # Skype for Business Server 2015
  if (lync_install["Product"] == "Skype for Business Server 2015")
  {
    path = hotfix_append_path(path:lync_install["path"], value:"Deployment");
    if (hotfix_check_fversion(file:"Microsoft.Rtc.Management.Deployment.Bootstrapper.dll", version:"6.0.9319.537", min_version:"6.0.9319.0", path:path, bulletin:bulletin, kb:"3061064", product:"Skype for Business Server 2015") == HCF_OLDER)
      vuln = TRUE;
  }
}

if (vuln)
{
  replace_kb_item(name:'www/'+port+'/XSS', value:TRUE);
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
