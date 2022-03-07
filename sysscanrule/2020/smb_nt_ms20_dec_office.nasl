##
# 
##

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.

include('compat.inc');

if (description)
{
  script_id(143555);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/14");

  script_cve_id("CVE-2020-17122", "CVE-2020-17128");
  script_xref(name:"MSKB", value:"4486698");
  script_xref(name:"MSKB", value:"4493140");
  script_xref(name:"MSKB", value:"4486757");
  script_xref(name:"MSFT", value:"MS20-4486698");
  script_xref(name:"MSFT", value:"MS20-4493140");
  script_xref(name:"MSFT", value:"MS20-4486757");
  script_xref(name:"IAVA", value:"2020-A-0557");

  script_name(english:"Security Updates for Microsoft Office Products (December 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. It is, therefore, affected by multiple remote code
execution vulnerabilities. An attacker can exploit these to bypass authentication and execute unauthorized arbitrary
commands.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://support.microsoft.com/en-us/help/4486698/security-update-for-office-2010-december-8-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b5beafd");
  # https://support.microsoft.com/en-us/help/4493140/security-update-for-office-2010-december-8-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6f9bfee");
  # https://support.microsoft.com/en-us/help/4486757/security-update-for-office-2016-december-8-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f71d8d98");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address these issues:  
  -KB4486698
  -KB4493140
  -KB4486757

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and manually
perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17128");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-12';
kbs = make_list(
  '4486698',
  '4493140',
  '4486757'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

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
    kb = '4486698';
    file = 'mso.dll';
    version = '14.0.7263.5000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:'14.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office14');
    kb = '4493140';
    file = 'graph.exe';
    version = '14.0.7263.5000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
  }
}

# Office 2016
if (office_vers['16.0'])
{
  office_sp = get_kb_item('SMB/Office/2016/SP');
  if (!isnull(office_sp) && office_sp == 0)
  {
    prod = 'Microsoft Office 2016';
    
    path = hotfix_get_officeprogramfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office16');

    # MSI graph.exe
    if (hotfix_check_fversion(file:'graph.exe', version:'16.0.5095.1000', channel:'MSI', channel_product:'Office', path:path, kb:'4486757', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
  }
}

# Office 2019
if (office_vers['16.0'])
{
  office_sp = get_kb_item('SMB/Office/2016/SP');
  if (!isnull(office_sp) && office_sp == 0)
  {
    prod2019 = 'Microsoft Office 2019';
    path = hotfix_get_officeprogramfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\root\\Office16');

    if (
      hotfix_check_fversion(file:'graph.exe', version:'16.0.12527.21416', channel:'Deferred', channel_version:'2002', channel_product:'Office', path:path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:'graph.exe', version:'16.0.11929.20984', channel:'Deferred', channel_product:'Office', path:path, bulletin:bulletin, product:prod) == HCF_OLDER ||

      hotfix_check_fversion(file:'graph.exe', version:'16.0.13328.20478', channel:'Enterprise Deferred', channel_product:'Office', channel_version:'2010', path:path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:'graph.exe', version:'16.0.13231.20620', channel:'Enterprise Deferred', channel_product:'Office', path:path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:'graph.exe', version:'16.0.13127.20910', channel:'First Release for Deferred', channel_product:'Office', path:path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:'graph.exe', version:'16.0.13426.20332', channel:'Current', channel_product:'Office', path:path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:'graph.exe', version:'16.0.13426.20332', channel:'2019 Retail', channel_product:'Office', path:path, bulletin:bulletin, product:prod2019) == HCF_OLDER ||
      hotfix_check_fversion(file:'graph.exe', version:'16.0.10369.20032', channel:'2019 Volume', channel_product:'Office', path:path, bulletin:bulletin, product:prod2019) == HCF_OLDER
    )
    vuln = TRUE;
  }
    checks = make_array(
      '16.0', make_nested_list(
        make_array('version', '16.0.12527.21416', 'channel', 'Deferred','channel_version', '2002'),
        make_array('version', '16.0.11929.20984', 'channel', 'Deferred'),
        make_array('version', '16.0.13328.20478', 'channel', 'Enterprise Deferred', 'channel_version', '2010'),
        make_array('version', '16.0.13231.20620', 'channel', 'Enterprise Deferred'),
        make_array('version', '16.0.13127.20910', 'channel', 'First Release for Deferred'),
        make_array('version', '16.0.13426.20332', 'channel', 'Current'),
        make_array('version', '16.0.13426.20332', 'channel', '2019 Retail'),
        make_array('version', '16.0.10369.20032', 'channel', '2019 Volume')
    )
  );
  if (hotfix_check_office_product(product:'Excel', checks:checks, bulletin:bulletin))
    vuln = TRUE;
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
