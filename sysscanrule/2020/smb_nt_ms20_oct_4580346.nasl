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
  script_id(141434);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/16");

  script_cve_id(
    "CVE-2020-0764",
    "CVE-2020-1167",
    "CVE-2020-1243",
    "CVE-2020-16876",
    "CVE-2020-16885",
    "CVE-2020-16887",
    "CVE-2020-16889",
    "CVE-2020-16891",
    "CVE-2020-16892",
    "CVE-2020-16894",
    "CVE-2020-16896",
    "CVE-2020-16897",
    "CVE-2020-16900",
    "CVE-2020-16902",
    "CVE-2020-16905",
    "CVE-2020-16909",
    "CVE-2020-16910",
    "CVE-2020-16911",
    "CVE-2020-16912",
    "CVE-2020-16914",
    "CVE-2020-16915",
    "CVE-2020-16916",
    "CVE-2020-16919",
    "CVE-2020-16920",
    "CVE-2020-16922",
    "CVE-2020-16923",
    "CVE-2020-16924",
    "CVE-2020-16927",
    "CVE-2020-16935",
    "CVE-2020-16936",
    "CVE-2020-16937",
    "CVE-2020-16939",
    "CVE-2020-16940",
    "CVE-2020-16972",
    "CVE-2020-16973",
    "CVE-2020-16974",
    "CVE-2020-16975",
    "CVE-2020-16976",
    "CVE-2020-16980"
  );
  script_xref(name:"MSKB", value:"4580346");
  script_xref(name:"MSFT", value:"MS20-4580346");
  script_xref(name:"IAVA", value:"2020-A-0457");
  script_xref(name:"IAVA", value:"2020-A-0458");

  script_name(english:"KB4580346: Windows 10 Version 1607 and Windows Server 2016 October 2020 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4580346.
It is, therefore, affected by multiple vulnerabilities :

  - A spoofing vulnerability exists when Windows incorrectly
    validates file signatures. An attacker who successfully
    exploited this vulnerability could bypass security
    features and load improperly signed files. In an attack
    scenario, an attacker could bypass security features
    intended to prevent improperly signed files from being
    loaded. The update addresses the vulnerability by
    correcting how Windows validates file signatures.
    (CVE-2020-16922)

  - A remote code execution vulnerability exists when the
    Windows Jet Database Engine improperly handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on a victim
    system. An attacker could exploit this vulnerability by
    enticing a victim to open a specially crafted file. The
    update addresses the vulnerability by correcting the way
    the Windows Jet Database Engine handles objects in
    memory. (CVE-2020-16924)

  - A remote code execution vulnerability exists when
    Windows Network Address Translation (NAT) fails to
    properly handle UDP traffic.  (CVE-2020-16894)

  - An elevation of privilege vulnerability exists when the
    Windows Storage VSP Driver improperly handles file
    operations. An attacker who successfully exploited this
    vulnerability could gain elevated privileges.
    (CVE-2020-16885)

  - A remote code execution vulnerability exists in the way
    that Microsoft Graphics Components handle objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute arbitrary code on a target
    system.  (CVE-2020-1167, CVE-2020-16923)

  - A remote code execution vulnerability exists when
    Windows Hyper-V on a host server fails to properly
    validate input from an authenticated user on a guest
    operating system.  (CVE-2020-16891)

  - An elevation of privilege vulnerability exists in the
    way that the Windows kernel image handles objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute code with elevated
    permissions.  (CVE-2020-16892)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface Plus
    (GDI+) handles objects in memory, allowing an attacker
    to retrieve information from a targeted system. By
    itself, the information disclosure does not allow
    arbitrary code execution; however, it could allow
    arbitrary code to be run if the attacker uses it in
    combination with another vulnerability.
    (CVE-2020-16914)

  - An elevation of privilege vulnerability exists in the
    Windows Installer when the Windows Installer fails to
    properly sanitize input leading to an insecure library
    loading behavior. A locally authenticated attacker could
    run arbitrary code with elevated system privileges. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights. The security update addresses the vulnerability
    by correcting the input sanitization error to preclude
    unintended elevation. (CVE-2020-16902)

  - An elevation of privilege vulnerability exists when the
    Windows Storage Services improperly handle file
    operations. An attacker who successfully exploited this
    vulnerability could gain elevated privileges.
    (CVE-2020-0764)

  - An information disclosure vulnerability exists in Remote
    Desktop Protocol (RDP) when an attacker connects to the
    target system using RDP and sends specially crafted
    requests. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2020-16896)

  - A remote code execution vulnerability exists in the way
    that the Windows Graphics Device Interface (GDI) handles
    objects in the memory. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2020-16911)

  - An information disclosure vulnerability exists when
    NetBIOS over TCP (NBT) Extensions (NetBT) improperly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could obtain information to
    further compromise the users system.  (CVE-2020-16897)

  - An elevation of privilege vulnerability exists when the
    Windows Application Compatibility Client Library
    improperly handles registry operations. An attacker who
    successfully exploited this vulnerability could gain
    elevated privileges.  (CVE-2020-16876, CVE-2020-16920)

  - A memory corruption vulnerability exists when Windows
    Media Foundation improperly handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could install programs; view, change, or delete data; or
    create new accounts with full user rights. There are
    multiple ways an attacker could exploit the
    vulnerability, such as by convincing a user to open a
    specially crafted document, or by convincing a user to
    visit a malicious webpage. The security update addresses
    the vulnerability by correcting how Windows Media
    Foundation handles objects in memory. (CVE-2020-16915)

  - An elevation of privilege vulnerability exists when the
    Windows User Profile Service (ProfSvc) improperly
    handles junction points. An attacker who successfully
    exploited this vulnerability could delete files and
    folders in an elevated context.  (CVE-2020-16940)

  - A security feature bypass vulnerability exists when
    Microsoft Windows fails to handle file creation
    permissions, which could allow an attacker to create
    files in a protected Unified Extensible Firmware
    Interface (UEFI) location.  (CVE-2020-16910)

  - An elevation of privilege vulnerability exists when
    Group Policy improperly checks access. An attacker who
    successfully exploited this vulnerability could run
    processes in an elevated context.  (CVE-2020-16939)

  - An elevation of privilege vulnerability exists in
    Windows Error Reporting (WER) when WER handles and
    executes files. The vulnerability could allow elevation
    of privilege if an attacker can successfully exploit it.
    An attacker who successfully exploited the vulnerability
    could gain greater access to sensitive information and
    system functionality.  (CVE-2020-16905, CVE-2020-16909)

  - A denial of service vulnerability exists when Microsoft
    Hyper-V on a host server fails to properly validate
    specific malicious data from a user on a guest operating
    system.  (CVE-2020-1243)

  - A denial of service vulnerability exists in Remote
    Desktop Protocol (RDP) when an attacker connects to the
    target system using RDP and sends specially crafted
    requests. An attacker who successfully exploited this
    vulnerability could cause the RDP service on the target
    system to stop responding.  (CVE-2020-16927)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Network Connections Service handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could execute code with
    elevated permissions.  (CVE-2020-16887)

  - An elevation of privilege vulnerability exists when the
    Windows Backup Service improperly handles file
    operations.  (CVE-2020-16912, CVE-2020-16936,
    CVE-2020-16972, CVE-2020-16973, CVE-2020-16974,
    CVE-2020-16975, CVE-2020-16976)

  - An information disclosure vulnerability exists when the
    .NET Framework improperly handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could disclose contents of an affected system's memory.
    (CVE-2020-16937)

  - An information disclosure vulnerability exists when the
    Windows KernelStream improperly handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2020-16889)

  - An elevation of privilege vulnerability exists when the
    Windows iSCSI Target Service improperly handles file
    operations. An attacker who successfully exploited this
    vulnerability could gain elevated privileges.
    (CVE-2020-16980)

  - An elevation of privilege vulnerability exists when
    Windows improperly handles COM object creation. An
    attacker who successfully exploited the vulnerability
    could run arbitrary code with elevated privileges.
    (CVE-2020-16916, CVE-2020-16935)

  - An elevation of privilege vulnerability exists when the
    Windows Event System improperly handles objects in
    memory.  (CVE-2020-16900)

  - An information disclosure vulnerability exists when the
    Windows Enterprise App Management Service improperly
    handles certain file operations. An attacker who
    successfully exploited this vulnerability could read
    arbitrary files. An attacker with unprivileged access to
    a vulnerable system could exploit this vulnerability.
    The security update addresses the vulnerability by
    ensuring the Windows Enterprise App Management Service
    properly handles file operations. (CVE-2020-16919)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4580346");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4580346.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16891");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/13");

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

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-10';
kbs = make_list(
  '4580346'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'10',
                   sp:0,
                   os_build:'14393',
                   rollup_date:'10_2020',
                   bulletin:bulletin,
                   rollup_kb_list:[4580346])
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
