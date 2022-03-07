include("compat.inc");

if (description)
{
  script_id(118918);
  script_version("1.9");
  script_cvs_date("Date: 2019/04/10 16:10:18");

  script_cve_id(
    "CVE-2018-8256",
    "CVE-2018-8407",
    "CVE-2018-8408",
    "CVE-2018-8415",
    "CVE-2018-8450",
    "CVE-2018-8476",
    "CVE-2018-8485",
    "CVE-2018-8544",
    "CVE-2018-8547",
    "CVE-2018-8549",
    "CVE-2018-8550",
    "CVE-2018-8552",
    "CVE-2018-8553",
    "CVE-2018-8561",
    "CVE-2018-8562",
    "CVE-2018-8563",
    "CVE-2018-8565"
  );
  script_bugtraq_id(
  105770,
  105774,
  105777,
  105778,
  105781,
  105786,
  105787,
  105789,
  105790,
  105791,
  105792,
  105794,
  105797,
  105801,
  105803,
  105805,
  105813
);
  script_xref(name:"MSKB", value:"4467703");
  script_xref(name:"MSKB", value:"4467697");
  script_xref(name:"MSFT", value:"MS18-4467703");
  script_xref(name:"MSFT", value:"MS18-4467697");

  script_name(english:"KB4467703: Windows 8.1 and Windows Server 2012 R2 November 2018 Security Update");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4467703
or cumulative update 4467697. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-8552)

  - A remote code execution vulnerability exists when
    Windows Search handles objects in memory. An attacker
    who successfully exploited this vulnerability could take
    control of the affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2018-8450)

  - A remote code execution vulnerability exists when
    PowerShell improperly handles specially crafted files.
    An attacker who successfully exploited this
    vulnerability could execute malicious code on a
    vulnerable system.  (CVE-2018-8256)

  - A security feature bypass exists when Windows
    incorrectly validates kernel driver signatures. An
    attacker who successfully exploited this vulnerability
    could bypass security features and load improperly
    signed drivers into the kernel. In an attack scenario,
    an attacker could bypass security features intended to
    prevent improperly signed drivers from being loaded by
    the kernel. The update addresses the vulnerability by
    correcting how Windows validates kernel driver
    signatures. (CVE-2018-8549)

  - An information disclosure vulnerability exists when
    DirectX improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system. An authenticated attacker could exploit this
    vulnerability by running a specially crafted
    application. The update addresses the vulnerability by
    correcting how DirectX handles objects in memory.
    (CVE-2018-8563)

  - A tampering vulnerability exists in PowerShell that
    could allow an attacker to execute unlogged code.
    (CVE-2018-8415)

  - A remote code execution vulnerability exists in the way
    that Windows Deployment Services TFTP Server handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could execute arbitrary code
    with elevated permissions on a target system.
    (CVE-2018-8476)

  - An information disclosure vulnerability exists when the
    win32k component improperly provides kernel information.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2018-8565)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2018-8544)

  - An elevation of privilege exists in Windows COM
    Aggregate Marshaler. An attacker who successfully
    exploited the vulnerability could run arbitrary code
    with elevated privileges.  (CVE-2018-8550)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly initializes objects in memory.
    (CVE-2018-8408)

  - A cross-site-scripting (XSS) vulnerability exists when
    an open source customization for Microsoft Active
    Directory Federation Services (AD FS) does not properly
    sanitize a specially crafted web request to an affected
    AD FS server. An authenticated attacker could exploit
    the vulnerability by sending a specially crafted request
    to an affected AD FS server. The attacker who
    successfully exploited the vulnerability could then
    perform cross-site scripting attacks on affected systems
    and run scripts in the security context of the current
    user. The attacks could allow the attacker to read
    content that the attacker is not authorized to read, use
    the victim's identity to take actions on the AD FS site
    on behalf of the user, such as change permissions and
    delete content, and inject malicious content in the
    browser of the user. The security update addresses the
    vulnerability by helping to ensure that the open source
    customization for AD FS properly sanitizes web requests.
    (CVE-2018-8547)

  - A remote code execution vulnerability exists in the way
    that Microsoft Graphics Components handle objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute arbitrary code on a target
    system.  (CVE-2018-8553)

  - An information disclosure vulnerability exists when
    &quot;Kernel Remote Procedure Call Provider&quot; driver
    improperly initializes objects in memory.
    (CVE-2018-8407)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2018-8562)

  - An elevation of privilege vulnerability exists when
    DirectX improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could run arbitrary code in kernel mode. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2018-8485, CVE-2018-8561)");
  #
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4467703/windows-8-1-update-kb4467703");
  #
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4467697/windows-8-1-update-kb4467697");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4467703 or Cumulative Update KB4467697.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8256");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by WebRAY, Inc.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS18-11";
kbs = make_list('4467703', '4467697');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"6.3",
                   sp:0,
                   rollup_date:"11_2018",
                   bulletin:bulletin,
                   rollup_kb_list:[4467703, 4467697])
)
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
