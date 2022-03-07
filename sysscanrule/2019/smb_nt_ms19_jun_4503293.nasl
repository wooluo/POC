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
  script_id(125825);
  script_version("1.6");
  script_cvs_date("Date: 2019/08/23 10:01:45");

  script_cve_id(
    "CVE-2019-0620",
    "CVE-2019-0722",
    "CVE-2019-0888",
    "CVE-2019-0904",
    "CVE-2019-0905",
    "CVE-2019-0906",
    "CVE-2019-0907",
    "CVE-2019-0908",
    "CVE-2019-0909",
    "CVE-2019-0920",
    "CVE-2019-0941",
    "CVE-2019-0943",
    "CVE-2019-0948",
    "CVE-2019-0959",
    "CVE-2019-0972",
    "CVE-2019-0973",
    "CVE-2019-0974",
    "CVE-2019-0983",
    "CVE-2019-0984",
    "CVE-2019-0986",
    "CVE-2019-0988",
    "CVE-2019-0989",
    "CVE-2019-0990",
    "CVE-2019-0991",
    "CVE-2019-0992",
    "CVE-2019-0993",
    "CVE-2019-0998",
    "CVE-2019-1003",
    "CVE-2019-1005",
    "CVE-2019-1007",
    "CVE-2019-1010",
    "CVE-2019-1012",
    "CVE-2019-1014",
    "CVE-2019-1017",
    "CVE-2019-1019",
    "CVE-2019-1021",
    "CVE-2019-1022",
    "CVE-2019-1023",
    "CVE-2019-1024",
    "CVE-2019-1025",
    "CVE-2019-1026",
    "CVE-2019-1027",
    "CVE-2019-1028",
    "CVE-2019-1038",
    "CVE-2019-1039",
    "CVE-2019-1040",
    "CVE-2019-1041",
    "CVE-2019-1043",
    "CVE-2019-1046",
    "CVE-2019-1050",
    "CVE-2019-1051",
    "CVE-2019-1052",
    "CVE-2019-1053",
    "CVE-2019-1054",
    "CVE-2019-1055",
    "CVE-2019-1064",
    "CVE-2019-1065",
    "CVE-2019-1069",
    "CVE-2019-1080",
    "CVE-2019-1081"
  );
  script_bugtraq_id(
    108570,
    108577,
    108581,
    108583,
    108585,
    108586,
    108587,
    108588,
    108591,
    108592,
    108593,
    108594,
    108595,
    108596,
    108597,
    108598,
    108599,
    108600,
    108602,
    108603,
    108604,
    108606,
    108607,
    108608,
    108609,
    108612,
    108613,
    108620,
    108624,
    108633,
    108638,
    108641,
    108644,
    108646,
    108647,
    108648,
    108649,
    108650,
    108651,
    108652,
    108653,
    108654,
    108655,
    108656,
    108657,
    108658,
    108659,
    108660,
    108662,
    108663,
    108664,
    108665,
    108666,
    108667,
    108668,
    108669,
    108670,
    108671,
    108708,
    108709
  );
  script_xref(name:"MSKB", value:"4503293");
  script_xref(name:"MSFT", value:"MS19-4503293");

  script_name(english:"KB4503293: Windows 10 Version 1903 June 2019 Security Update");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4503293.
It is, therefore, affected by multiple vulnerabilities :

  - An elevation of privilege exists in Windows Audio
    Service. An attacker who successfully exploited the
    vulnerability could run arbitrary code with elevated
    privileges.  (CVE-2019-1007, CVE-2019-1021,
    CVE-2019-1022, CVE-2019-1026, CVE-2019-1027,
    CVE-2019-1028)

  - An elevation of privilege vulnerability exists when
    Windows improperly handles calls to Advanced Local
    Procedure Call (ALPC). An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    the security context of the local system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2019-0943)

  - A remote code execution vulnerability exists when
    Windows Hyper-V on a host server fails to properly
    validate input from an authenticated user on a guest
    operating system.  (CVE-2019-0620, CVE-2019-0722)

  - A security feature bypass vulnerability exists where a
    NETLOGON message is able to obtain the session key and
    sign messages.  (CVE-2019-1019)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2019-1014, CVE-2019-1017)

  - A tampering vulnerability exists in Microsoft Windows
    when a man-in-the-middle attacker is able to
    successfully bypass the NTLM MIC (Message Integrity
    Check) protection. An attacker who successfully
    exploited this vulnerability could gain the ability to
    downgrade NTLM security features.  (CVE-2019-1040)

  - An information disclosure vulnerability exists when the
    scripting engine does not properly handle objects in
    memory in Microsoft Edge. An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system.  (CVE-2019-0990,
    CVE-2019-1023)

  - An elevation of privilege vulnerability exists when the
    Windows Common Log File System (CLFS) driver improperly
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context.  (CVE-2019-0959, CVE-2019-0984)

  - An elevation of privilege vulnerability exists in the
    Windows Installer when the Windows Installer fails to
    properly sanitize input leading to an insecure library
    loading behavior. A locally authenticated attacker could
    run arbitrary code with elevated system privileges. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights. The security update addresses the vulnerability
    by correcting the input sanitization error to preclude
    unintended elevation. (CVE-2019-0973)

  - A remote code execution vulnerability exists when the
    Windows Jet Database Engine improperly handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on a victim
    system. An attacker could exploit this vulnerability by
    enticing a victim to open a specially crafted file. The
    update addresses the vulnerability by correcting the way
    the Windows Jet Database Engine handles objects in
    memory. (CVE-2019-0904, CVE-2019-0905, CVE-2019-0906,
    CVE-2019-0907, CVE-2019-0908, CVE-2019-0909,
    CVE-2019-0974)

  - An information disclosure vulnerability exists in the
    Windows Event Viewer (eventvwr.msc) when it improperly
    parses XML input containing a reference to an external
    entity. An attacker who successfully exploited this
    vulnerability could read arbitrary files via an XML
    external entity (XXE) declaration.  (CVE-2019-0948)

  - A security feature bypass vulnerability exists in Edge
    that allows for bypassing Mark of the Web Tagging
    (MOTW). Failing to set the MOTW means that a large
    number of Microsoft security technologies are bypassed.
    (CVE-2019-1054)

  - A remote code execution vulnerability exists in the way
    that comctl32.dll handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2019-1043)

  - A remote code execution vulnerability exists in the way
    the scripting engine handles objects in memory in
    Microsoft browsers. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2019-0920, CVE-2019-1005, CVE-2019-1055,
    CVE-2019-1080)

  - A remote code execution vulnerability exists in the way
    that Microsoft browsers access objects in memory. The
    vulnerability could corrupt memory in a way that could
    allow an attacker to execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2019-1038)

  - An elevation of privilege vulnerability exists when
    Windows AppX Deployment Service (AppXSVC) improperly
    handles hard links. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context. An attacker could then install
    programs; view, change or delete data.  (CVE-2019-1064)

  - A denial of service vulnerability exists when Windows
    improperly handles objects in memory. An attacker who
    successfully exploited the vulnerability could cause a
    target system to stop responding.  (CVE-2019-1025)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2019-0988)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly initializes objects in memory.
    (CVE-2019-1039)

  - A remote code execution vulnerability exists in the way
    that the Chakra scripting engine handles objects in
    memory in Microsoft Edge. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user.  (CVE-2019-0989, CVE-2019-0991,
    CVE-2019-0992, CVE-2019-0993, CVE-2019-1003,
    CVE-2019-1024, CVE-2019-1051, CVE-2019-1052)

  - This security update corrects a denial of service in the
    Local Security Authority Subsystem Service (LSASS)
    caused when an authenticated attacker sends a specially
    crafted authentication request. A remote attacker who
    successfully exploited this vulnerability could cause a
    denial of service on the target system's LSASS service,
    which triggers an automatic reboot of the system. The
    security update addresses the vulnerability by changing
    the way that LSASS handles specially crafted
    authentication requests. (CVE-2019-0972)

  - An information disclosure vulnerability exists when
    affected Microsoft browsers improperly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2019-1081)

  - An elevation of privilege vulnerability exists when the
    Windows Shell fails to validate folder shortcuts. An
    attacker who successfully exploited the vulnerability
    could elevate privileges by escaping a sandbox.
    (CVE-2019-1053)

  - An information disclosure vulnerability exists when the
    Windows GDI component improperly discloses the contents
    of its memory. An attacker who successfully exploited
    the vulnerability could obtain information to further
    compromise the users system. There are multiple ways an
    attacker could exploit the vulnerability, such as by
    convincing a user to open a specially crafted document,
    or by convincing a user to visit an untrusted webpage.
    The security update addresses the vulnerability by
    correcting how the Windows GDI component handles objects
    in memory. (CVE-2019-1010, CVE-2019-1012, CVE-2019-1046,
    CVE-2019-1050)

  - A remote code execution vulnerability exists in the way
    that ActiveX Data Objects (ADO) handle objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute arbitrary code with the
    victim users privileges. An attacker could craft a
    website that exploits the vulnerability and then
    convince a victim user to visit the website. The
    security update addresses the vulnerability by modifying
    how ActiveX Data Objects handle objects in memory.
    (CVE-2019-0888)

  - A denial of service exists in Microsoft IIS Server when
    the optional request filtering feature improperly
    handles requests. An attacker who successfully exploited
    this vulnerability could perform a temporary denial of
    service against pages configured to use request
    filtering.  (CVE-2019-0941)

  - An elevation of privilege vulnerability exists in the
    way the Task Scheduler Service validates certain file
    operations. An attacker who successfully exploited the
    vulnerability could gain elevated privileges on a victim
    system.  (CVE-2019-1069)

  - An elevation of privilege vulnerability exists when the
    Storage Service improperly handles file operations. An
    attacker who successfully exploited this vulnerability
    could gain elevated privileges on the victim system.
    (CVE-2019-0983, CVE-2019-0998)

  - An elevation of privilege vulnerability exists when the
    Windows kernel fails to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights.  (CVE-2019-1041, CVE-2019-1065)

  - An elevation of privilege vulnerability exists when the
    Windows User Profile Service (ProfSvc) improperly
    handles symlinks. An attacker who successfully exploited
    this vulnerability could delete files and folders in an
    elevated context.  (CVE-2019-0986)");
  # https://support.microsoft.com/en-us/help/4503293/windows-10-update-kb4503293
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
  "Apply Cumulative Update KB4503293.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0888");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

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

bulletin = "MS19-06";
kbs = make_list('4503293');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"18362",
                   rollup_date:"06_2019",
                   bulletin:bulletin,
                   rollup_kb_list:[4503293])
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
