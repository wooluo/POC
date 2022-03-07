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
  script_id(123975);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/13 17:57:55");

  script_cve_id(
    "CVE-2019-0817",
    "CVE-2019-0858"
  );
  script_xref(name:"MSKB", value:"4491413");
  script_xref(name:"MSKB", value:"4487563");
  script_xref(name:"MSFT", value:"MS19-4491413");
  script_xref(name:"MSFT", value:"MS19-4487563");

  script_name(english:"Security Updates for Exchange (April 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A spoofing vulnerability exists in Microsoft Exchange
    Server when Outlook Web Access (OWA) fails to properly
    handle web requests. An attacker who successfully
    exploited the vulnerability could perform script or
    content injection attacks, and attempt to trick the user
    into disclosing sensitive information. An attacker could
    also redirect the user to a malicious website that could
    spoof content or the vulnerability could be used as a
    pivot to chain an attack with other vulnerabilities in
    web services.  (CVE-2019-0817, CVE-2019-0858)");
  # https://support.microsoft.com/en-us/help/4491413/update-rollup-27-for-exchange-server-2010-service-pack-3
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4487563/description-of-the-security-update-for-microsoft-exchange-server
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4491413
  -KB4487563");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0817");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_exchange_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS19-04';
kbs = make_list(
  "4487563", # Exchange Server 2013 / 2016 / 2019
  "4491413"  # Exchange Server 2010
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

install = get_single_install(app_name:"Microsoft Exchange");

path = install["path"];
version = install["version"];
release = install["RELEASE"];

if (
  release != 140 &&
  release != 150 &&
  release != 151 &&
  release != 152
)  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

if (!empty_or_null(install["SP"]))
  sp = install["SP"];
if (!empty_or_null(install["CU"]))
  cu = install["CU"];

if (release == 140 && sp != 3)
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

if (release == 140) # Exchange Server 2010
{
  if (sp == 3)
  {
    fixedver = "14.3.452.0";
    kb = '4491413';
  }
}
else if (release == 150) # Exchange Server 2013
{
  if (cu == 22)
  {
    fixedver = "15.0.1473.3";
    kb = '4487563';
  }
}
else if (release == 151) # Exchange Server 2016
{
  if (cu == 11)
  {
    fixedver = "15.1.1591.16";
    kb = '4487563';
  }
  else if (cu == 12)
  {
    fixedver = "15.1.1713.6";
    kb = '4487563';
  }
}
else if (release == 152) # Exchange Server 2019
{
  if (cu < 1)
  {
    fixedver = "15.2.221.16";
    kb = '4487563';
  }
  else if (cu == 1)
  {
    fixedver = "15.2.330.7";
    kb = '4487563';
  }
}

if (fixedver && hotfix_is_vulnerable(path:hotfix_append_path(path:path, value:"Bin"), file:"ExSetup.exe", version:fixedver, bulletin:bulletin, kb:kb))
{
  port = kb_smb_transport();
  replace_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  replace_kb_item(name:'www/' + port + '/XSS', value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

