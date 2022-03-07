#
# 
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(138600);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/20");

  script_cve_id("CVE-2020-1350");
  script_xref(name:"MSKB", value:"4558998");
  script_xref(name:"MSKB", value:"4565483");
  script_xref(name:"MSKB", value:"4565483");
  script_xref(name:"MSKB", value:"4565503");
  script_xref(name:"MSKB", value:"4565511");
  script_xref(name:"MSKB", value:"4565524");
  script_xref(name:"MSKB", value:"4565529");
  script_xref(name:"MSKB", value:"4565535");
  script_xref(name:"MSKB", value:"4565536");
  script_xref(name:"MSKB", value:"4565537");
  script_xref(name:"MSKB", value:"4565539");
  script_xref(name:"MSKB", value:"4565540");
  script_xref(name:"MSKB", value:"4565541");
  script_xref(name:"MSFT", value:"MS20-4558998");
  script_xref(name:"MSFT", value:"MS20-4565483");
  script_xref(name:"MSFT", value:"MS20-4565483");
  script_xref(name:"MSFT", value:"MS20-4565503");
  script_xref(name:"MSFT", value:"MS20-4565511");
  script_xref(name:"MSFT", value:"MS20-4565524");
  script_xref(name:"MSFT", value:"MS20-4565529");
  script_xref(name:"MSFT", value:"MS20-4565535");
  script_xref(name:"MSFT", value:"MS20-4565536");
  script_xref(name:"MSFT", value:"MS20-4565537");
  script_xref(name:"MSFT", value:"MS20-4565539");
  script_xref(name:"MSFT", value:"MS20-4565540");
  script_xref(name:"MSFT", value:"MS20-4565541");
  script_xref(name:"IAVA", value:"2020-A-0299");

  script_name(english:"Windows DNS Server RCE (CVE-2020-1350)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is, 
therefore, affected by a remote code execution vulnerability:

  - A remote code execution vulnerability exists in Windows
    Domain Name System servers when they fail to properly
    handle requests. An attacker who successfully exploited
    the vulnerability could run arbitrary code in the
    context of the Local System Account. Windows servers
    that are configured as DNS servers are at risk from this
    vulnerability.  (CVE-2020-1350)");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1350
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a916fa9");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate security update or mitigation as described in the Microsoft advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1350");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_hotfixes_fcheck.inc');
include('smb_hotfixes.inc');
include('smb_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-07';

get_kb_item_or_exit('SMB/Registry/Enumerated');
my_os = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
my_os_build = get_kb_item('SMB/WindowsVersionBuild');
my_prod = get_kb_item_or_exit('SMB/ProductName');
sp = 0;
vuln = FALSE;
mitigated = FALSE;

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0',  win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

## Set kbs and sp
if(my_os == '6.0' && 'server' >< tolower(my_prod))
{
  kbs = make_list('4565536','4565529');
  sp = 2;
}
else if(my_os == '6.1' && 'server' >< tolower(my_prod))
{
  kbs = make_list('4565524','4565539');
  sp = 1;
}
else if(my_os == '6.2' && 'server' >< tolower(my_prod))
{
  kbs = make_list('4565537','4565535');
}
else if(my_os == '6.3' && 'server' >< tolower(my_prod))
{
  kbs = make_list('4565541','4565540');
}
else if(my_os == '10' && 'server' >< tolower(my_prod))
{
    if(my_os_build == '14393') kbs = make_list('4565511');
    else if(my_os_build == '17763') kbs = make_list('4558998');
    else if(my_os_build == '18362') kbs = make_list('4565483');
    else if(my_os_build == '18363') kbs = make_list('4565483');
    else if(my_os_build == '19041') kbs = make_list('4565503');
}
else
    audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( my_os == '10' )
{   
  vuln = smb_check_rollup( os:'10',
                           sp:0,
                           os_build:my_os_build,
                           rollup_date:'07_2020',
                           bulletin:bulletin,
                           rollup_kb_list:kbs
                        );
}
else
{
  vuln = smb_check_rollup( os:my_os, 
                           sp:sp,
                           rollup_date:'07_2020',
                           bulletin:bulletin,
                           rollup_kb_list:kbs
                        );
}

## Check mitigation
mitigation_key = 'SYSTEM\\CurrentControlSet\\Services\\DNS\\Parameters\\TcpReceivePacketSize';
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
packetsize = get_registry_value(handle:hklm, item:mitigation_key);
RegCloseKey(handle:hklm);
close_registry(close:TRUE);

if (!isnull(packetsize) && (packetsize == 65280))
    mitigated = TRUE;

if(vuln && !mitigated)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
