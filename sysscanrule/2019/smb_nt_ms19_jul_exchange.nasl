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
  script_id(126581);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/12 12:39:17");

  script_cve_id(
    "CVE-2019-1084",
    "CVE-2019-1136",
    "CVE-2019-1137"
  );
  script_xref(name:"MSKB", value:"4509410");
  script_xref(name:"MSKB", value:"4509409");
  script_xref(name:"MSKB", value:"4509408");
  script_xref(name:"MSFT", value:"MS19-4509410");
  script_xref(name:"MSFT", value:"MS19-4509409");
  script_xref(name:"MSFT", value:"MS19-4509408");
  script_xref(name:"IAVA", value:"2019-A-0229");

  script_name(english:"Security Updates for Exchange (July 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A cross-site-scripting (XSS) vulnerability exists when
    Microsoft Exchange Server does not properly sanitize a
    specially crafted web request to an affected Exchange
    server. An authenticated attacker could exploit the
    vulnerability by sending a specially crafted request to
    an affected server. The attacker who successfully
    exploited the vulnerability could then perform cross-
    site scripting attacks on affected systems and run
    script in the security context of the current user. The
    attacks could allow the attacker to read content that
    the attacker is not authorized to read, use the victim's
    identity to take actions on the Exchange server on
    behalf of the user, such as change permissions and
    delete content, and inject malicious content in the
    browser of the user. The security update addresses the
    vulnerability by helping to ensure that Exchange Server
    properly sanitizes web requests. (CVE-2019-1137)

  - An information disclosure vulnerability exists when
    Exchange allows creation of entities with Display Names
    having non-printable characters. An authenticated
    attacker could exploit this vulnerability by creating
    entities with invalid display names, which, when added
    to conversations, remain invisible. This security update
    addresses the issue by validating display names upon
    creation in Microsoft Exchange, and by rendering invalid
    display names correctly in Microsoft Outlook clients.
    (CVE-2019-1084)

  - An elevation of privilege vulnerability exists in
    Microsoft Exchange Server. An attacker who successfully
    exploited this vulnerability could gain the same rights
    as any other user of the Exchange server. This could
    allow the attacker to perform activities such as
    accessing the mailboxes of other users. Exploitation of
    this vulnerability requires Exchange Web Services (EWS)
    to be enabled and in use in an affected environment.
    (CVE-2019-1136)");
  # https://support.microsoft.com/en-us/help/4509410/description-of-the-security-update-for-microsoft-exchange-server-2010
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4509409/description-of-the-security-update-for-microsoft-exchange-server-2013
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4509408/description-of-the-security-update-for-microsoft-exchange-server-2019
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4509410
  -KB4509409
  -KB4509408");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1137");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_exchange_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('misc_func.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS19-06';
kbs = make_list(
  '4509410', # Exchange Server 2010 SP3
  '4509409', # Exchange Server 2013 CU 23 / 2016 CU 12-13
  '4509408'  # Exchange Server 2019 CU 1-2
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

install = get_single_install(app_name:'Microsoft Exchange');

path = install['path'];
version = install['version'];
release = install['RELEASE'];

if (
  release != 140 &&
  release != 150 &&
  release != 151 &&
  release != 152
)  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

if (!empty_or_null(install['SP']))
  sp = install['SP'];
if (!empty_or_null(install['CU']))
  cu = install['CU'];

xss = FALSE;

if (release == 140) # Exchange Server 2010
{
  # 2010 is using SP's not CU's
  if (sp == 3)
  {
    fixedver = '14.3.468.0';
    kb = '4509410';
  }
  else if (sp != 3)
    audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);
}
else if (release == 150) # Exchange Server 2013
{
  xss = TRUE;
  if (cu == 23)
  {
    fixedver = '15.0.1497.3';
    kb = '4509409';
  }
}
else if (release == 151) # Exchange Server 2016
{
  xss = TRUE;
  if (cu == 12)
  {
    fixedver = '15.1.1713.8';
    kb = '4509409';
  }
  else if (cu == 13)
  {
    fixedver = '15.1.1779.4';
    kb = '4509409';
  }
}
else if (release == 152) # Exchange Server 2019
{
  xss = TRUE;
  if (cu == 1)
  {
    fixedver = '15.2.330.9';
    kb = '4509408';
  }
  else if (cu == 2)
  {
    fixedver = '15.2.397.5';
    kb = '4509408';
  }
}

if (
  fixedver &&
  hotfix_is_vulnerable(path:hotfix_append_path(path:path, value:"Bin"), file:'ExSetup.exe', version:fixedver, bulletin:bulletin, kb:kb)
)
{
  port = kb_smb_transport();
  if (xss) replace_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  replace_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

