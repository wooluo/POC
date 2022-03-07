#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126953);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/23 18:52:58");

  script_cve_id(
    "CVE-2019-3969",
    "CVE-2019-3970",
    "CVE-2019-3971",
    "CVE-2019-3972"
  );
  script_xref(name:"TRA", value:"TRA-2019-34");

  script_name(english:"Comodo Antivirus / Internet Security Multiple Vulnerabilities");
  script_summary(english:"Checks version of Comodo Internet Security");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an antivirus application installed that 
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Comodo security product installed on the remote Windows
host is affected by multiple vulnerabilities:

  - A Local Privilege Escalation due to CmdAgent's handling
    of COM clients. A local process can bypass the signature
    check enforced by CmdAgent via process hollowing which
    can then allow the process to invoke sensitive COM
    methods in CmdAgent such as writing to the registry with
    SYSTEM privileges.(CVE-2019-3969)

  - An Arbitrary File Write due to Cavwp.exe handling of
    Comodo's Antivirus database. Cavwp.exe loads Comodo
    antivirus definition database in unsecured global
    section objects, allowing a local low privileged process
    to modify this data directly and change virus
    signatures. (CVE-2019-3970)

  - A local Denial of Service affecting CmdVirth.exe via its
    LPC port cmdvrtLPCServerPort. A low privileged local
    process can connect to this port and send an
    LPC_DATAGRAM, which triggers an Access Violation due to
    hardcoded NULLs used for Source parameter in a memcpy
    operation that is called for this handler. This results
    in CmdVirth.exe and its child svchost.exe instances to
    terminate. (CVE-2019-3971)

  - A Denial of Service affecting CmdAgent.exe via an
    unprotected section object <GUID>_CisSharedMemBuff. This
    section object is exposed by CmdAgent and contains a
    SharedMemoryDictionary object, which allows a low
    privileged process to modify the object data causing
    CmdAgent.exe to crash. (CVE-2019-3972)

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://www.WebRAY.com/security/research/tra-2019-34
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:"No known fix, refer to vendor for further information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3969");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("comodo_internet_security_installed.nasl");
  script_require_keys("SMB/Comodo Internet Security/Version", "SMB/Comodo Internet Security/Path");
  
  exit(0);
}

include("vcf.inc");

app = "Comodo Internet Security";
app_info = vcf::get_app_info(app:app);

if (report_paranoia < 2)
{
  if(ver_compare(ver:app_info.version, fix:"12.0.0.6810")>0)
    audit(AUDIT_POTENTIAL_VULN, app, app_info.version);
  constraints = [{ "min_version" : "0", "max_version":"12.0.0.6810", "fixed_display":"No known fix, refer to vendor for further information."}];
}
else
  constraints = [{ "min_version" : "0", "fixed_display":"No known fix, refer to vendor for further information."}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
