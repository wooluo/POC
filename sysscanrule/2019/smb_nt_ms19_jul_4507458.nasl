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
  script_id(126576);
  script_version("1.6");
  script_cvs_date("Date: 2019/08/16 15:34:48");

  script_cve_id(
    "CVE-2019-0880",
    "CVE-2019-0887",
    "CVE-2019-0999",
    "CVE-2019-1001",
    "CVE-2019-1004",
    "CVE-2019-1006",
    "CVE-2019-1056",
    "CVE-2019-1059",
    "CVE-2019-1062",
    "CVE-2019-1063",
    "CVE-2019-1067",
    "CVE-2019-1071",
    "CVE-2019-1073",
    "CVE-2019-1082",
    "CVE-2019-1083",
    "CVE-2019-1085",
    "CVE-2019-1086",
    "CVE-2019-1087",
    "CVE-2019-1088",
    "CVE-2019-1089",
    "CVE-2019-1091",
    "CVE-2019-1092",
    "CVE-2019-1093",
    "CVE-2019-1094",
    "CVE-2019-1095",
    "CVE-2019-1096",
    "CVE-2019-1097",
    "CVE-2019-1102",
    "CVE-2019-1103",
    "CVE-2019-1104",
    "CVE-2019-1107",
    "CVE-2019-1108",
    "CVE-2019-1113",
    "CVE-2019-1125",
    "CVE-2019-1130"
  );
  script_xref(name:"MSKB", value:"4507458");
  script_xref(name:"MSFT", value:"MS19-4507458");

  script_name(english:"KB4507458: Windows 10 July 2019 Security Update (SWAPGS)");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4507458.
It is, therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when
    DirectX improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could run arbitrary code in kernel mode. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2019-0999)

  - A remote code execution vulnerability exists in .NET
    software when the software fails to check the source
    markup of a file. An attacker who successfully exploited
    the vulnerability could run arbitrary code in the
    context of the current user. If the current user is
    logged on with administrative user rights, an attacker
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2019-1113)

  - A local elevation of privilege vulnerability exists in
    how splwow64.exe handles certain calls. An attacker who
    successfully exploited the vulnerability could elevate
    privileges on an affected system from low-integrity to
    medium-integrity. This vulnerability by itself does not
    allow arbitrary code execution; however, it could allow
    arbitrary code to be run if the attacker uses it in
    combination with another vulnerability (such as a remote
    code execution vulnerability or another elevation of
    privilege vulnerability) that is capable of leveraging
    the elevated privileges when code execution is
    attempted. (CVE-2019-0880)

  - An elevation of privilege vulnerability exists in
    rpcss.dll when the RPC service Activation Kernel
    improperly handles an RPC request.  (CVE-2019-1089)

  - An information disclosure vulnerability exists when the
    Windows RDP client improperly discloses the contents of
    its memory. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2019-1108)

  - An information disclosure vulnerability exists when the
    win32k component improperly provides kernel information.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2019-1096)

  - An elevation of privilege vulnerability exists in
    Microsoft Windows where a certain dll, with Local
    Service privilege, is vulnerable to race planting a
    customized dll. An attacker who successfully exploited
    this vulnerability could potentially elevate privilege
    to SYSTEM. The update addresses this vulnerability by
    requiring system privileges for a certain DLL.
    (CVE-2019-1082)

  - A remote code execution vulnerability exists in the way
    the scripting engine handles objects in memory in
    Microsoft browsers. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2019-1001)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2019-1063)

  - A remote code execution vulnerability exists in the way
    that Microsoft browsers access objects in memory. The
    vulnerability could corrupt memory in a way that could
    allow an attacker to execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2019-1104)

  - An information disclosure vulnerability exists when
    DirectWrite improperly discloses the contents of its
    memory. An attacker who successfully exploited the
    vulnerability could obtain information to further
    compromise the users system. There are multiple ways an
    attacker could exploit the vulnerability, such as by
    convincing a user to open a specially crafted document,
    or by convincing a user to visit an untrusted webpage.
    The security update addresses the vulnerability by
    correcting how DirectWrite handles objects in memory.
    (CVE-2019-1093, CVE-2019-1097)

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
    in memory. (CVE-2019-1094, CVE-2019-1095)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system. An authenticated attacker could exploit this
    vulnerability by running a specially crafted
    application. The update addresses the vulnerability by
    correcting how the Windows kernel handles objects in
    memory. (CVE-2019-1071)

  - An elevation of privilege vulnerability exists when the
    Windows kernel fails to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights.  (CVE-2019-1067)

  - An elevation of privilege exists in Windows Audio
    Service. An attacker who successfully exploited the
    vulnerability could run arbitrary code with elevated
    privileges.  (CVE-2019-1086, CVE-2019-1087,
    CVE-2019-1088)

  - An elevation of privilege vulnerability exists when
    Windows AppX Deployment Service (AppXSVC) improperly
    handles hard links. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context. An attacker could then install
    programs; view, change or delete data.  (CVE-2019-1130)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2019-1004, CVE-2019-1056, CVE-2019-1059)

  - A remote code execution vulnerability exists in Remote
    Desktop Services formerly known as Terminal Services
    when an authenticated attacker abuses clipboard
    redirection. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on the victim
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2019-0887)

  - An elevation of privilege vulnerability exists in the
    way that the wlansvc.dll handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2019-1085)

  - A denial of service vulnerability exists when Microsoft
    Common Object Runtime Library improperly handles web
    requests. An attacker who successfully exploited this
    vulnerability could cause a denial of service against a
    .NET web application. A remote unauthenticated attacker
    could exploit this vulnerability by issuing specially
    crafted requests to the .NET application. The update
    addresses the vulnerability by correcting how the .NET
    web application handles web requests. (CVE-2019-1083)

  - A remote code execution vulnerability exists in the way
    that the Chakra scripting engine handles objects in
    memory in Microsoft Edge. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user.  (CVE-2019-1062, CVE-2019-1092,
    CVE-2019-1103, CVE-2019-1107)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2019-1073)

  - A remote code execution vulnerability exists in the way
    that the Windows Graphics Device Interface (GDI) handles
    objects in the memory. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2019-1102)

  - An authentication bypass vulnerability exists in Windows
    Communication Foundation (WCF) and Windows Identity
    Foundation (WIF), allowing signing of SAML tokens with
    arbitrary symmetric keys. This vulnerability allows an
    attacker to impersonate another user, which can lead to
    elevation of privileges. The vulnerability exists in
    WCF, WIF 3.5 and above in .NET Framework, WIF 1.0
    component in Windows, WIF Nuget package, and WIF
    implementation in SharePoint. An unauthenticated
    attacker can exploit this by signing a SAML token with
    any arbitrary symmetric key. This security update
    addresses the issue by ensuring all versions of WCF and
    WIF validate the key used to sign SAML tokens correctly.
    (CVE-2019-1006)

  - An information disclosure vulnerability exists when
    Unistore.dll fails to properly handle objects in memory.
    An attacker who successfully exploited the vulnerability
    could potentially disclose memory contents of an
    elevated process.  (CVE-2019-1091)
    
  - An information disclosure vulnerability exists when
    certain central processing units (CPU) speculatively
    access memory. An attacker who successfully exploited
    the vulnerability could read privileged data across
    trust boundaries. (CVE-2019-1125)");
  # https://support.microsoft.com/en-us/help/4507458/windows-10-update-kb4507458
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
  "Apply Cumulative Update KB4507458.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1102");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/09");

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

bulletin = "MS19-07";
kbs = make_list('4507458');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10240",
                   rollup_date:"07_2019",
                   bulletin:bulletin,
                   rollup_kb_list:[4507458])
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
