##
# 
##
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(148476);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/20");

  script_cve_id(
    "CVE-2021-28480",
    "CVE-2021-28481",
    "CVE-2021-28482",
    "CVE-2021-28483"
  );
  script_xref(name:"MSKB", value:"5001779");
  script_xref(name:"MSFT", value:"MS21-5001779");
  script_xref(name:"IAVA", value:"2021-A-0160");

  script_name(english:"Security Updates for Microsoft Exchange Server (April 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker could exploit this to
    execute unauthorized arbitrary code. (CVE-2021-28483, CVE-2021-28482, 
    CVE-2021-28481, CVE-2021-28480");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2019-2016-and-2013-april-13-2021-kb5001779-8e08f3b3-fc7b-466c-bbb7-5d5aa16ef064
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bdeeea7");
  # https://msrc-blog.microsoft.com/2021/04/13/april-2021-update-tuesday-packages-now-available/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b66291c9");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB5001779");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28480");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/13");

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
include('misc_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

exit_if_productname_not_server();

var bulletin = 'MS21-04';
var kbs = make_list(
  '5001779'   # 2013 CU 23 / 2016 CU19-20 / 2019 CU8-9
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

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

if (release == 150) # Exchange Server 2013
{
  if (cu == 23)
  {
    fixedver = '15.0.1497.15';
  }
  else if (cu < 23)
  {
    unsupported_cu = TRUE;
  }

  kb = '5001779';
}
else if (release == 151) # Exchange Server 2016
{
  if (cu == 19)
  {
    fixedver = '15.1.2176.12';
  }
  else if (cu == 20)
  {
    fixedver = '15.1.2242.8';
  }
  else if (cu < 20)
  {
    unsupported_cu = TRUE;
  }

  kb = '5001779';
}
else if (release == 152) # Exchange Server 2019
{
  if (cu == 8)
  {
    fixedver = '15.2.792.13';
  }
  else if (cu == 9)
  {
    fixedver = '15.2.858.10';
  }
  else if (cu < 9)
  {
    unsupported_cu = TRUE;
  }

  kb = '5001779';
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
    bulletin:bulletin, kb:kb);;

  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
