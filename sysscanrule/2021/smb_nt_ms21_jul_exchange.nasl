
##
# 
##



include('compat.inc');

if (description)
{
  script_id(151664);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/16");

  script_cve_id(
    "CVE-2021-31196",
    "CVE-2021-31206",
    "CVE-2021-33768",
    "CVE-2021-34470"
  );
  script_xref(name:"MSKB", value:"5003611");
  script_xref(name:"MSFT", value:"MS21-5003611");
  script_xref(name:"MSKB", value:"5003612");
  script_xref(name:"MSFT", value:"MS21-5003612");
  script_xref(name:"MSKB", value:"5004778");
  script_xref(name:"MSFT", value:"MS21-5004778");
  script_xref(name:"MSKB", value:"5004779");
  script_xref(name:"MSFT", value:"MS21-5004779");
  script_xref(name:"MSKB", value:"5004780");
  script_xref(name:"MSFT", value:"MS21-5004780");
  script_xref(name:"IAVA", value:"2021-A-0315");

  script_name(english:"Security Updates for Exchange (July 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host is missing security
updates. It is, therefore, affected by multiple vulnerabilities:

- A remote code execution vulnerability. An attacker can exploit this to bypass
  authentication and execute unauthorized arbitrary commands.  (CVE-2021-31196,
  CVE-2021-31206)

- An elevation of privilege vulnerability. An attacker can exploit this to gain
  elevated privileges. (CVE-2021-33768, CVE-2021-34470)

Note: Nessus is unable to determine if the latest Active Directory schema has
been applied.");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2016-july-13-2021-kb5004779-81e40da3-60db-4c09-bf11-b8c1e0c1b77d
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a44a0d8a");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2019-july-13-2021-kb5004780-fc5b3fa1-1f7a-47b0-8014-699257256bb5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f529b54");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2013-july-13-2021-kb5004778-f532100d-a9c1-4f2c-bc36-baec95881011
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ecec1115");
  # https://support.microsoft.com/en-us/topic/cumulative-update-21-for-exchange-server-2016-kb5003611-b7ba1656-abba-4a0b-9be9-dac45095d969
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51a55048");
  # https://support.microsoft.com/en-us/topic/cumulative-update-10-for-exchange-server-2019-kb5003612-b1434cad-3fbc-4dc3-844d-82568e8d4344
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c76ecd10");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following KBs to address these issues:
 - KB5003611
 - KB5003612
 - KB5004778
 - KB5004779
 - KB5004780");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31206");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_exchange_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}


include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

exit_if_productname_not_server();

var bulletin = 'MS21-07';
var kbs = make_list(
  '5004778', # 2013
  '5004779', # 2016
  '5004780', # 2019
  '5003611', # 2016 Addendum
  '5003612'  # 2019 Addendum
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

var install = get_single_install(app_name:'Microsoft Exchange');

var path = install['path'];
var version = install['version'];
var release = install['RELEASE'];
var port = kb_smb_transport();

if (
    release != 150 &&  # 2013
    release != 151 &&  # 2016
    release != 152     # 2019
)  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

var cu = 0;
var sp = 0;
if (!empty_or_null(install['CU']))
  cu = install['CU'];
if (!empty_or_null(install['SP']))
  sp = install['SP'];

var fixedver, unsupported_cu, kb;
if (release == 150) # Exchange Server 2013
{
  if (cu == 23)
  {
    fixedver = '15.0.1497.23';
  }
  else if (cu < 23)
  {
    unsupported_cu = TRUE;
  }

  kb = '5004778';
}
else if (release == 151) # Exchange Server 2016
{
  if (cu == 20)
  {
    fixedver = '15.1.2242.12';
  }
  else if (cu == 21)
  {
    fixedver = '15.1.2308.14';
  }
  else if (cu < 20)
  {
    unsupported_cu = TRUE;
  }

  kb = '5004779';
}
else if (release == 152) # Exchange Server 2019
{
  if (cu == 9)
  {
    fixedver = '15.2.858.15';
  }
  else if (cu == 10)
  {
    fixedver = '15.2.922.13';
  }
  else if (cu < 9)
  {
    unsupported_cu = TRUE;
  }

  kb = '5004780';
}

if ((fixedver && hotfix_is_vulnerable(path:hotfix_append_path(path:path, value:"Bin"), file:'ExSetup.exe', version:fixedver, bulletin:bulletin, kb:kb))
  || (unsupported_cu && report_paranoia == 2))
{
  if (unsupported_cu)
    hotfix_add_report('The Microsoft Exchange Server installed at ' + path +
    ' has an unsupported Cumulative Update (CU) installed and may be ' +
    'vulnerable to the CVEs contained within the advisory. Unsupported ' +
    'Exchange CU versions are not typically included in Microsoft ' +
    'advisories and are not indicated as affected.\n',
    bulletin:bulletin, kb:kb);

  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
