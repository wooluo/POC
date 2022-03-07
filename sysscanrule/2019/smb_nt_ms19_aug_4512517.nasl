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
  script_id(127850);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/16 15:34:48");

  script_cve_id(
    "CVE-2019-0714",
    "CVE-2019-0715",
    "CVE-2019-0716",
    "CVE-2019-0718",
    "CVE-2019-0720",
    "CVE-2019-0723",
    "CVE-2019-0736",
    "CVE-2019-1030",
    "CVE-2019-1057",
    "CVE-2019-1078",
    "CVE-2019-1133",
    "CVE-2019-1139",
    "CVE-2019-1140",
    "CVE-2019-1143",
    "CVE-2019-1144",
    "CVE-2019-1145",
    "CVE-2019-1146",
    "CVE-2019-1147",
    "CVE-2019-1148",
    "CVE-2019-1149",
    "CVE-2019-1150",
    "CVE-2019-1151",
    "CVE-2019-1152",
    "CVE-2019-1153",
    "CVE-2019-1155",
    "CVE-2019-1156",
    "CVE-2019-1157",
    "CVE-2019-1158",
    "CVE-2019-1159",
    "CVE-2019-1162",
    "CVE-2019-1163",
    "CVE-2019-1164",
    "CVE-2019-1168",
    "CVE-2019-1172",
    "CVE-2019-1176",
    "CVE-2019-1177",
    "CVE-2019-1178",
    "CVE-2019-1179",
    "CVE-2019-1180",
    "CVE-2019-1181",
    "CVE-2019-1182",
    "CVE-2019-1183",
    "CVE-2019-1186",
    "CVE-2019-1187",
    "CVE-2019-1192",
    "CVE-2019-1193",
    "CVE-2019-1194",
    "CVE-2019-1195",
    "CVE-2019-1197",
    "CVE-2019-1198",
    "CVE-2019-1206",
    "CVE-2019-1212",
    "CVE-2019-9506",
    "CVE-2019-9511",
    "CVE-2019-9512",
    "CVE-2019-9513",
    "CVE-2019-9514",
    "CVE-2019-9518"
  );
  script_xref(name:"MSKB", value:"4512517");
  script_xref(name:"MSFT", value:"MS19-4512517");
  script_xref(name:"IAVA", value:"2019-A-0284");
  script_xref(name:"IAVA", value:"2019-A-0286");
  script_xref(name:"IAVA", value:"2019-A-0293");

  script_name(english:"KB4512517: Windows 10 Version 1607 and Windows Server 2016 August 2019 Security Update");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4512517.
It is, therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when
    Windows improperly handles calls to Advanced Local
    Procedure Call (ALPC). An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    the security context of the local system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2019-1162)

  - A security feature bypass vulnerability exists when
    Microsoft browsers improperly handle requests of
    different origins. The vulnerability allows Microsoft
    browsers to bypass Same-Origin Policy (SOP)
    restrictions, and to allow requests that should
    otherwise be ignored. An attacker who successfully
    exploited the vulnerability could force the browser to
    send data that would otherwise be restricted.
    (CVE-2019-1192)

  - An information disclosure vulnerability exists when the
    Microsoft Windows Graphics Component improperly handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system.  (CVE-2019-1148,
    CVE-2019-1153)

  - A denial of service vulnerability exists when the
    XmlLite runtime (XmlLite.dll) improperly parses XML
    input. An attacker who successfully exploited this
    vulnerability could cause a denial of service against an
    XML application. A remote unauthenticated attacker could
    exploit this vulnerability by issuing specially crafted
    requests to an XML application. The update addresses the
    vulnerability by correcting how the XmlLite runtime
    parses XML input. (CVE-2019-1187)

  - An elevation of privilege vulnerability exists when
    DirectX improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could run arbitrary code in kernel mode. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2019-1176)

  - A remote code execution vulnerability exists when the
    Windows Jet Database Engine improperly handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on a victim
    system. An attacker could exploit this vulnerability by
    enticing a victim to open a specially crafted file. The
    update addresses the vulnerability by correcting the way
    the Windows Jet Database Engine handles objects in
    memory. (CVE-2019-1146, CVE-2019-1147, CVE-2019-1155,
    CVE-2019-1156, CVE-2019-1157)

  - A denial of service vulnerability exists in the HTTP/2
    protocol stack (HTTP.sys) when HTTP.sys improperly
    parses specially crafted HTTP/2 requests. An attacker
    who successfully exploited the vulnerability could
    create a denial of service condition, causing the target
    system to become unresponsive.  (CVE-2019-9511,
    CVE-2019-9512, CVE-2019-9513, CVE-2019-9514,
    CVE-2019-9518)

  - <h1>Executive Summary</h1> Microsoft is aware of the
    Bluetooth BR/EDR (basic rate/enhanced data rate, known
    as &quot;Bluetooth Classic&quot;) key negotiation
    vulnerability that exists at the hardware specification
    level of any BR/EDR Bluetooth device. An attacker could
    potentially be able to negotiate the offered key length
    down to 1 byte of entropy, from a maximum of 16 bytes.
    (CVE-2019-9506)

  - A remote code execution vulnerability exists in the way
    that the Chakra scripting engine handles objects in
    memory in Microsoft Edge. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user.  (CVE-2019-1139, CVE-2019-1140,
    CVE-2019-1195, CVE-2019-1197)

  - An elevation of privilege exists in the p2pimsvc service
    where an attacker who successfully exploited the
    vulnerability could run arbitrary code with elevated
    privileges.  (CVE-2019-1168)

  - An information disclosure vulnerability exists when the
    Windows Graphics component improperly handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system. An authenticated attacker
    could exploit this vulnerability by running a specially
    crafted application. The update addresses the
    vulnerability by correcting how the Windows Graphics
    Component handles objects in memory. (CVE-2019-1078)

  - An elevation of privilege vulnerability exists in the
    way that the wcmsvc.dll handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2019-1180, CVE-2019-1186)

  - A memory corruption vulnerability exists in the Windows
    Server DHCP service when an attacker sends specially
    crafted packets to a DHCP failover server. An attacker
    who successfully exploited the vulnerability could cause
    the DHCP service to become nonresponsive.
    (CVE-2019-1206)

  - An elevation of privilege vulnerability exists in the
    way that the unistore.dll handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2019-1179)

  - An elevation of privilege exists in SyncController.dll.
    An attacker who successfully exploited the vulnerability
    could run arbitrary code with elevated privileges.
    (CVE-2019-1198)

  - An elevation of privilege vulnerability exists in the
    way that the ssdpsrv.dll handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2019-1178)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited the vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2019-1144,
    CVE-2019-1145, CVE-2019-1149, CVE-2019-1150,
    CVE-2019-1151, CVE-2019-1152)

  - A security feature bypass exists when Windows
    incorrectly validates CAB file signatures. An attacker
    who successfully exploited this vulnerability could
    inject code into a CAB file without invalidating the
    file's signature.  (CVE-2019-1163)

  - An elevation of privilege vulnerability exists when the
    Windows kernel fails to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights.  (CVE-2019-1159, CVE-2019-1164)

  - A remote code execution vulnerability exists in Remote
    Desktop Services formerly known as Terminal Services
    when an unauthenticated attacker connects to the target
    system using RDP and sends specially crafted requests.
    This vulnerability is pre-authentication and requires no
    user interaction. An attacker who successfully exploited
    this vulnerability could execute arbitrary code on the
    target system. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2019-1181, CVE-2019-1182)

  - A memory corruption vulnerability exists in the Windows
    DHCP client when an attacker sends specially crafted
    DHCP responses to a client. An attacker who successfully
    exploited the vulnerability could run arbitrary code on
    the client machine.  (CVE-2019-0736)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2019-1133, CVE-2019-1194)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2019-1183)

  - An elevation of privilege vulnerability exists in the
    way that the rpcss.dll handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2019-1177)

  - A remote code execution vulnerability exists in the way
    that Microsoft browsers access objects in memory. The
    vulnerability could corrupt memory in a way that could
    allow an attacker to execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2019-1193)

  - An information disclosure vulnerability exists when
    Microsoft Edge improperly handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2019-1030)

  - An information disclosure vulnerability exists in Azure
    Active Directory (AAD) Microsoft Account (MSA) during
    the login request session. An attacker who successfully
    exploited the vulnerability could take over a user's
    account.  (CVE-2019-1172)

  - A denial of service vulnerability exists when Microsoft
    Hyper-V Network Switch on a host server fails to
    properly validate input from a privileged user on a
    guest operating system. An attacker who successfully
    exploited the vulnerability could cause the host server
    to crash.  (CVE-2019-0714, CVE-2019-0715, CVE-2019-0718,
    CVE-2019-0723)

  - A denial of service vulnerability exists when Windows
    improperly handles objects in memory. An attacker who
    successfully exploited the vulnerability could cause a
    target system to stop responding.  (CVE-2019-0716)

  - An information disclosure vulnerability exists when the
    Windows GDI component improperly discloses the contents
    of its memory. An attacker who successfully exploited
    the vulnerability could obtain information to further
    compromise a users system. There are multiple ways an
    attacker could exploit the vulnerability, such as by
    convincing a user to open a specially crafted document
    or by convincing a user to visit an untrusted webpage.
    The update addresses the vulnerability by correcting how
    the Windows GDI component handles objects in memory.
    (CVE-2019-1143, CVE-2019-1158)

  - A remote code execution vulnerability exists when
    Windows Hyper-V Network Switch on a host server fails to
    properly validate input from an authenticated user on a
    guest operating system.  (CVE-2019-0720)

  - A memory corruption vulnerability exists in the Windows
    Server DHCP service when processing specially crafted
    packets. An attacker who successfully exploited the
    vulnerability could cause the DHCP server service to
    stop responding.  (CVE-2019-1212)

  - A remote code execution vulnerability exists when the
    Microsoft XML Core Services MSXML parser processes user
    input. An attacker who successfully exploited the
    vulnerability could run malicious code remotely to take
    control of the users system.  (CVE-2019-1057)");
  # https://support.microsoft.com/en-us/help/4512517/windows-10-update-kb4512517
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
  "Apply Cumulative Update KB4512517.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1181");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

bulletin = "MS19-08";
kbs = make_list('4512517');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"14393",
                   rollup_date:"08_2019",
                   bulletin:bulletin,
                   rollup_kb_list:[4512517])
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
