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
  script_id(122124);
  script_version("1.8");
  script_cvs_date("Date: 2019/08/23 10:01:45");

  script_cve_id(
    "CVE-2019-0590",
    "CVE-2019-0591",
    "CVE-2019-0593",
    "CVE-2019-0595",
    "CVE-2019-0596",
    "CVE-2019-0597",
    "CVE-2019-0598",
    "CVE-2019-0599",
    "CVE-2019-0600",
    "CVE-2019-0601",
    "CVE-2019-0602",
    "CVE-2019-0605",
    "CVE-2019-0606",
    "CVE-2019-0610",
    "CVE-2019-0613",
    "CVE-2019-0615",
    "CVE-2019-0616",
    "CVE-2019-0618",
    "CVE-2019-0619",
    "CVE-2019-0621",
    "CVE-2019-0623",
    "CVE-2019-0625",
    "CVE-2019-0626",
    "CVE-2019-0627",
    "CVE-2019-0628",
    "CVE-2019-0630",
    "CVE-2019-0631",
    "CVE-2019-0632",
    "CVE-2019-0633",
    "CVE-2019-0634",
    "CVE-2019-0635",
    "CVE-2019-0636",
    "CVE-2019-0640",
    "CVE-2019-0641",
    "CVE-2019-0642",
    "CVE-2019-0644",
    "CVE-2019-0645",
    "CVE-2019-0649",
    "CVE-2019-0651",
    "CVE-2019-0652",
    "CVE-2019-0654",
    "CVE-2019-0655",
    "CVE-2019-0656",
    "CVE-2019-0657",
    "CVE-2019-0658",
    "CVE-2019-0659",
    "CVE-2019-0660",
    "CVE-2019-0662",
    "CVE-2019-0663",
    "CVE-2019-0676"
  );
  script_xref(name:"MSKB", value:"4487020");
  script_xref(name:"MSFT", value:"MS19-4487020");

  script_name(english:"KB4487020: Windows 10 Version 1703 February 2019 Security Update");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4487020. 
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in .NET
    Framework and Visual Studio software when the software
    fails to check the source markup of a file. An attacker
    who successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2019-0613)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2019-0606)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2019-0623)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2019-0621)

  - A vulnerability exists in Microsoft Chakra JIT server.
    An attacker who successfully exploited this
    vulnerability could gain elevated privileges. The
    vulnerability by itself does not allow arbitrary code to
    run. However, this vulnerability could be used in
    conjunction with one or more vulnerabilities (for
    example a remote code execution vulnerability and
    another elevation of privilege vulnerability) to take
    advantage of the elevated privileges when running. The
    security update addresses the vulnerability by modifying
    how Microsoft Chakra handles constructorCaches.
    (CVE-2019-0649)

  - An information disclosure vulnerability exists when the
    win32k component improperly provides kernel information.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2019-0628)

  - A remote code execution vulnerability exists in the way
    that the Windows Graphics Device Interface (GDI) handles
    objects in the memory. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2019-0618,
    CVE-2019-0662)

  - An information vulnerability exists when Windows
    improperly discloses file information. Successful
    exploitation of the vulnerability could allow the
    attacker to read the contents of files on disk.
    (CVE-2019-0636)

  - A remote code execution vulnerability exists when the
    Windows Jet Database Engine improperly handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on a victim
    system. An attacker could exploit this vulnerability by
    enticing a victim to open a specially crafted file. The
    update addresses the vulnerability by correcting the way
    the Windows Jet Database Engine handles objects in
    memory. (CVE-2019-0595, CVE-2019-0596, CVE-2019-0597,
    CVE-2019-0598, CVE-2019-0599, CVE-2019-0625)

  - An elevation of privilege vulnerability exists when the
    Windows kernel fails to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights.  (CVE-2019-0656)

  - A remote code execution vulnerability exists when
    Microsoft Edge improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that enables an attacker to execute arbitrary code in
    the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2019-0634,
    CVE-2019-0645)

  - An information disclosure vulnerability exists when the
    Human Interface Devices (HID) component improperly
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could obtain information to
    further compromise the victims system.  (CVE-2019-0600,
    CVE-2019-0601)

  - An elevation of privilege vulnerability exists when the
    Storage Service improperly handles file operations. An
    attacker who successfully exploited this vulnerability
    could gain elevated privileges on the victim system.
    (CVE-2019-0659)

  - An information disclosure vulnerability exists when
    Internet Explorer improperly handles objects in memory.
    An attacker who successfully exploited this
    vulnerability could test for the presence of files on
    disk. For an attack to be successful, an attacker must
    persuade a user to open a malicious website. The
    security update addresses the vulnerability by changing
    the way Internet Explorer handles objects in memory.
    (CVE-2019-0676)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Microsoft Edge. The vulnerability could corrupt memory
    in such a way that an attacker could execute arbitrary
    code in the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2019-0590,
    CVE-2019-0591, CVE-2019-0593, CVE-2019-0605,
    CVE-2019-0610, CVE-2019-0640, CVE-2019-0642,
    CVE-2019-0644, CVE-2019-0651, CVE-2019-0652,
    CVE-2019-0655)

  - A memory corruption vulnerability exists in the Windows
    Server DHCP service when an attacker sends specially
    crafted packets to a DHCP server. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code on the DHCP server.  (CVE-2019-0626)

  - An information disclosure vulnerability exists when
    Windows Hyper-V on a host operating system fails to
    properly validate input from an authenticated user on a
    guest operating system.  (CVE-2019-0635)

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
    in memory. (CVE-2019-0602, CVE-2019-0615, CVE-2019-0616,
    CVE-2019-0619, CVE-2019-0660)

  - An information disclosure vulnerability exists when the
    scripting engine does not properly handle objects in
    memory in Microsoft Edge. An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system.  (CVE-2019-0658)

  - A security feature bypass vulnerability exists in
    Windows which could allow an attacker to bypass Device
    Guard. An attacker who successfully exploited this
    vulnerability could circumvent a User Mode Code
    Integrity (UMCI) policy on the machine.  (CVE-2019-0627,
    CVE-2019-0631, CVE-2019-0632)

  - A vulnerability exists in certain .Net Framework API's
    and Visual Studio in the way they parse URL's. An
    attacker who successfully exploited this vulnerability
    could use it to bypass security logic intended to ensure
    that a user-provided URL belonged to a specific hostname
    or a subdomain of that hostname. This could be used to
    cause privileged communication to be made to an
    untrusted service as if it was a trusted service.
    (CVE-2019-0657)

  - A security feature bypass vulnerability exists in
    Microsoft Edge handles whitelisting. Edge depends on a
    default whitelist of sites where Adobe Flash will load
    without user interaction. Because the whitelist was not
    scheme-aware, an attacker could use a man in the middle
    attack to cause Flash policies to be bypassed and
    arbitrary Flash content to be loaded without user
    interaction. The security update addresses the
    vulnerability by modifying how affected Microsoft Edge
    handles whitelisting. (CVE-2019-0641)

  - A spoofing vulnerability exists when Microsoft browsers
    improperly handles specific redirects. An attacker who
    successfully exploited this vulnerability could trick a
    user into believing that the user was on a legitimate
    website. The specially crafted website could either
    spoof content or serve as a pivot to chain an attack
    with other vulnerabilities in web services.
    (CVE-2019-0654)

  - A remote code execution vulnerability exists in the way
    that the Microsoft Server Message Block 2.0 (SMBv2)
    server handles certain requests. An attacker who
    successfully exploited the vulnerability could gain the
    ability to execute code on the target server.
    (CVE-2019-0630, CVE-2019-0633)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly initializes objects in memory.
    To exploit this vulnerability, an authenticated attacker
    could run a specially crafted application. An attacker who
    successfully exploited this vulnerability could obtain
    information to further compromise the user's system.
    (CVE-2019-0663)");
  # https://support.microsoft.com/en-us/help/4487020/windows-10-update-kb4487020
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
  "Apply Cumulative Update KB4487020.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0630");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/12");

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

bulletin = "MS19-02";
kbs = make_list('4487020');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"15063",
                   rollup_date:"02_2019",
                   bulletin:bulletin,
                   rollup_kb_list:[4487020])
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
