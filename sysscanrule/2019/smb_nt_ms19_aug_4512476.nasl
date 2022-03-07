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
  script_id(127842);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/16 15:34:48");

  script_cve_id(
    "CVE-2019-0714",
    "CVE-2019-0715",
    "CVE-2019-0716",
    "CVE-2019-0720",
    "CVE-2019-0736",
    "CVE-2019-1057",
    "CVE-2019-1078",
    "CVE-2019-1133",
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
    "CVE-2019-1154",
    "CVE-2019-1155",
    "CVE-2019-1156",
    "CVE-2019-1157",
    "CVE-2019-1158",
    "CVE-2019-1159",
    "CVE-2019-1162",
    "CVE-2019-1164",
    "CVE-2019-1168",
    "CVE-2019-1169",
    "CVE-2019-1177",
    "CVE-2019-1178",
    "CVE-2019-1183",
    "CVE-2019-1187",
    "CVE-2019-1194",
    "CVE-2019-1212",
    "CVE-2019-1213",
    "CVE-2019-1228"
  );
  script_xref(name:"MSKB", value:"4512476");
  script_xref(name:"MSKB", value:"4512491");
  script_xref(name:"MSFT", value:"MS19-4512476");
  script_xref(name:"MSFT", value:"MS19-4512491");
  script_xref(name:"IAVA", value:"2019-A-0284");

  script_name(english:"KB4512491: Windows Server 2008 August 2019 Security Update");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4512491
or cumulative update 4512476. It is, therefore, affected by
multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when
    Windows improperly handles calls to Advanced Local
    Procedure Call (ALPC). An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    the security context of the local system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2019-1162)

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
    (CVE-2019-1143, CVE-2019-1154, CVE-2019-1158)

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

  - An elevation of privilege exists in the p2pimsvc service
    where an attacker who successfully exploited the
    vulnerability could run arbitrary code with elevated
    privileges.  (CVE-2019-1168)

  - An elevation of privilege vulnerability exists in
    Windows when the Windows kernel-mode driver fails to
    properly handle objects in memory. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code in kernel mode. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2019-1169)

  - An information disclosure vulnerability exists when the
    Windows Graphics component improperly handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system. An authenticated attacker
    could exploit this vulnerability by running a specially
    crafted application. The update addresses the
    vulnerability by correcting how the Windows Graphics
    Component handles objects in memory. (CVE-2019-1078)

  - A remote code execution vulnerability exists when the
    Microsoft XML Core Services MSXML parser processes user
    input. An attacker who successfully exploited the
    vulnerability could run malicious code remotely to take
    control of the users system.  (CVE-2019-1057)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited the vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2019-1144,
    CVE-2019-1145, CVE-2019-1149, CVE-2019-1150,
    CVE-2019-1151, CVE-2019-1152)

  - An elevation of privilege vulnerability exists when the
    Windows kernel fails to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights.  (CVE-2019-1159, CVE-2019-1164)

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

  - An elevation of privilege vulnerability exists in the
    way that the rpcss.dll handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2019-1177)

  - A denial of service vulnerability exists when Microsoft
    Hyper-V Network Switch on a host server fails to
    properly validate input from a privileged user on a
    guest operating system. An attacker who successfully
    exploited the vulnerability could cause the host server
    to crash.  (CVE-2019-0714, CVE-2019-0715)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2019-1183)

  - A denial of service vulnerability exists when Windows
    improperly handles objects in memory. An attacker who
    successfully exploited the vulnerability could cause a
    target system to stop responding.  (CVE-2019-0716)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2019-1228)

  - A remote code execution vulnerability exists when
    Windows Hyper-V Network Switch on a host server fails to
    properly validate input from an authenticated user on a
    guest operating system.  (CVE-2019-0720)

  - A memory corruption vulnerability exists in the Windows
    Server DHCP service when processing specially crafted
    packets. An attacker who successfully exploited the
    vulnerability could cause the DHCP server service to
    stop responding.  (CVE-2019-1212)

  - An elevation of privilege vulnerability exists in the
    way that the ssdpsrv.dll handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2019-1178)

  - A memory corruption vulnerability exists in the Windows
    Server DHCP service when an attacker sends specially
    crafted packets to a DHCP server. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code on the DHCP server.  (CVE-2019-1213)");
  # https://support.microsoft.com/en-us/help/4512486/windows-7-update-kb4512486
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4512476/windows-server-2008-update-kb4512476
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4512491/windows-server-2008-update-kb4512491
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4512491 or Cumulative Update KB4512476.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0720");

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
kbs = make_list('4512491', '4512476');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Vista" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"6.0",
                   sp:2,
                   rollup_date:"08_2019",
                   bulletin:bulletin,
                   rollup_kb_list:[4512491, 4512476])
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
