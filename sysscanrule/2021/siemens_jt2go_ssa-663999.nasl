##
# 
##


include('compat.inc');

if (description)
{
  script_id(149326);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/10");

  script_cve_id(
    "CVE-2020-26989",
    "CVE-2020-26990",
    "CVE-2020-26991",
    "CVE-2020-26998",
    "CVE-2020-26999",
    "CVE-2020-27000",
    "CVE-2020-27001",
    "CVE-2020-27002",
    "CVE-2020-27003",
    "CVE-2020-27004",
    "CVE-2020-27005",
    "CVE-2020-27006",
    "CVE-2020-27007",
    "CVE-2020-27008",
    "CVE-2020-28394",
    "CVE-2021-25173",
    "CVE-2021-25174",
    "CVE-2021-25175",
    "CVE-2021-25176",
    "CVE-2021-25177",
    "CVE-2021-25178"
  );
  script_xref(name:"IAVA", value:"2021-A-0049");

  script_name(english:"Siemens JT2Go < 13.1.0.1 Multiple Vulnerabilities (SSA-663999)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Siemens JT2Go installed on the remote Windows hosts is prior to 13.1.0.1. It is, therefore, affected by
multiple vulnerabilities, including the following:

  - A vulnerability has been identified in JT2Go. Affected applications lack proper validation of
    user-supplied data when parsing of PAR files. This could result in a stack based buffer overflow. An
    attacker could leverage this vulnerability to execute code in the context of the current process.
    (CVE-2020-26989)

  - A vulnerability has been identified in JT2Go. Affected applications lack proper validation of
    user-supplied data when parsing ASM files. A crafted ASM file can trigger a type confusion condition. An
    attacker can leverage this vulnerability to execute code in the context of the current process.
    (CVE-2020-26990)

  - A vulnerability has been identified in JT2Go. Affected applications lack proper validation of
    user-supplied data when parsing ASM files. This could lead to pointer dereferences of a value obtained
    from untrusted source. An attacker could leverage this vulnerability to execute code in the context of the
    current process. (CVE-2020-26991)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://cert-portal.siemens.com/productcert/pdf/ssa-663999.pdf");
  script_set_attribute(attribute:"solution", value:
"Update JT2Go to version 13.1.0.1 (File version 13.1.0.21004)");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26989");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:siemens:jt2go");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("siemens_jt2go_win_installed.nbin");
  script_require_keys("installed_sw/Siemens JT2Go");

  exit(0);
}


include('vcf.inc');

var app_info = vcf::get_app_info(app:'Siemens JT2Go', win_local:TRUE);

var constraints = [
  { 'fixed_version': '13.1.0.21004', 'fixed_display':'13.1.0.1 (File version 13.1.0.21004)' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
