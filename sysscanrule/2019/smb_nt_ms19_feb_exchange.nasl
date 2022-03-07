#
# (C) WebRAY Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(122129);
  script_version("1.4");
  script_cvs_date("Date: 2019/04/11 12:53:49");

  script_cve_id(
    "CVE-2018-18223",
    "CVE-2018-18224",
    "CVE-2018-3147",
    "CVE-2018-3217",
    "CVE-2018-3218",
    "CVE-2018-3219",
    "CVE-2018-3220",
    "CVE-2018-3221",
    "CVE-2018-3222",
    "CVE-2018-3223",
    "CVE-2018-3224",
    "CVE-2018-3225",
    "CVE-2018-3226",
    "CVE-2018-3227",
    "CVE-2018-3228",
    "CVE-2018-3229",
    "CVE-2018-3230",
    "CVE-2018-3231",
    "CVE-2018-3232",
    "CVE-2018-3233",
    "CVE-2018-3234",
    "CVE-2018-3302",
    "CVE-2019-0686",
    "CVE-2019-0724"
  );
  script_xref(name:"MSKB", value:"4345836");
  script_xref(name:"MSKB", value:"4471391");
  script_xref(name:"MSKB", value:"4471392");
  script_xref(name:"MSKB", value:"4487052");
  script_xref(name:"MSFT", value:"MS19-4345836");
  script_xref(name:"MSFT", value:"MS19-4471391");
  script_xref(name:"MSFT", value:"MS19-4471392");
  script_xref(name:"MSFT", value:"MS19-4487052");

  script_name(english:"Security Updates for Exchange (February 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host is missing
security updates. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple Vulnerabilites with the included libraries from
    Oracle Outside. (CVE-2018-18223, CVE-2018-18224,
    CVE-2018-3147, CVE-2018-3217, CVE-2018-3218, CVE-2018-3219,
    CVE-2018-3220, CVE-2018-3221, CVE-2018-3222, CVE-2018-3223,
    CVE-2018-3224, CVE-2018-3225, CVE-2018-3226, CVE-2018-3227,
    CVE-2018-3228, CVE-2018-3229, CVE-2018-3230, CVE-2018-3231,
    CVE-2018-3232, CVE-2018-3233, CVE-2018-3234, CVE-2018-3302)

  - An elevation of privilege vulnerability exists in
    Exchange Web Services and Push Notifications. An
    unauthenticated, remote attacker can exploit, via a
    man-in-the-middle attack forwarding an authentication
    request to the Domain Controller, to gain any users
    privileges. (CVE-2019-0686)

  - An elevation of privilege vulnerability exists in
    Exchange Web Services and Push Notifications. An
    unauthenticated, remote attacker can exploit, via a
    man-in-the-middle attack forwarding an authentication
    request to the Domain Controller, to gain Domain
    Administrator privileges. (CVE-2019-0724)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4345836");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4471391");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4471392");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4487052");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4345836
  -KB4471391
  -KB4471392
  -KB4487052");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0724");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/12");

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

bulletin = 'MS19-02';
kbs = make_list(
  "4345836", # Exchange Server 2013
  "4471391", # Exchange Server 2019
  "4471392", # Exchange Server 2016
  "4487052"  # Exchange Server 2010
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

if (release == 140 && sp != 3)
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

if (release == 140) # Exchange Server 2010
{
  if (sp == 3)
  {
    fixedver = "14.3.442.0";
    kb = '4487052';
  }
}
else if (release == 150) # Exchange Server 2013
{
  if (cu < 22)
  {
    fixedver = "15.0.1473.3";
    kb = '4345836';
  }
}
else if (release == 151) # Exchange Server 2016
{
  if (cu < 12)
  {
    fixedver = "15.1.1713.5";
    kb = '4471392';
  }
}
else if (release == 152) # Exchange Server 2019
{
  if (cu < 1)
  {
    fixedver = "15.2.330.5";
    kb = '4471391';
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

