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
  script_id(121022);
  script_version("1.4");
  script_cvs_date("Date: 2019/02/26  4:50:09");

  script_cve_id(
    "CVE-2019-0586",
    "CVE-2019-0588"
  );
  script_xref(name:"MSKB", value:"4468742");
  script_xref(name:"MSKB", value:"4471389");
  script_xref(name:"MSFT", value:"MS19-4468742");
  script_xref(name:"MSFT", value:"MS19-4471389");

  script_name(english:"Security Updates for Exchange (January 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - An information disclosure vulnerability exists when the
    Microsoft Exchange PowerShell API grants calendar
    contributors more view permissions than intended.
    (CVE-2019-0588)

  - A remote code execution vulnerability exists in
    Microsoft Exchange software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the System user. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts. Exploitation of the
    vulnerability requires that a specially crafted email be
    sent to a vulnerable Exchange server. The security
    update addresses the vulnerability by correcting how
    Microsoft Exchange handles objects in memory.
    (CVE-2019-0586)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4468742");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4471389");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4468742
  -KB4471389");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0586");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/08");

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

bulletin = 'MS19-01';
kbs = make_list(
  "4468742",
  "4471389"
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

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

if (
  (release == 140 && sp != 3) ||
  (release == 150 && cu != 21) ||
  (release == 151 && cu != 10 && cu != 11) ||
  (release == 152 && cu != 0)
)  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

if (release == 140) # Exchange Server 2010
{
  if (sp == 3)
  {
    fixedver = "14.3.435.0";
    kb = '4468742';
  }
}
else if (release == 150) # Exchange Server 2013
{
  if (cu == 21)
  {
    fixedver = "15.0.1395.10";
    kb = '4471389';
  }
}
else if (release == 151) # Exchange Server 2016
{
  if (cu == 10)
  {
    fixedver = "15.1.1531.10";
    kb = '4471389';
  }
  else if (cu == 11)
  {
    fixedver = "15.1.1591.13";
    kb = '4471389';
  }
}
else if (release == 152) # Exchange Server 2019
{
  if (cu == 0)
  {
    fixedver = "15.2.221.14";
    kb = '4471389';
  }
}

if (fixedver && hotfix_is_vulnerable(path:hotfix_append_path(path:path, value:"Bin"), file:"ExSetup.exe", version:fixedver, bulletin:bulletin, kb:kb))
{
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

