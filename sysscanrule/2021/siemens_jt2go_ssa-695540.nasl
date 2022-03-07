
##
# 
##



include('compat.inc');

if (description)
{
  script_id(150140);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id(
    "CVE-2020-26991",
    "CVE-2020-26998",
    "CVE-2020-26999",
    "CVE-2020-27001",
    "CVE-2020-27002"
  );

  script_name(english:"Siemens JT2Go < 13.1.0.2 Multiple Vulnerabilities (SSA-695540)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Siemens JT2Go installed on the remote Windows hosts is prior to 13.1.0.2. It is, therefore, affected by
multiple vulnerabilities, including the following:

  - Affected applications lack proper validation of user-supplied data when parsing ASM files. This could
    lead to pointer dereferences of a value obtained from untrusted source. An attacker could leverage
    this vulnerability to execute code in the context of the current process. (CVE-2020-26991)

  - Affected applications lack proper validation of user-supplied data when parsing of PAR files. This
    could result in a memory access past the end of an allocated buffer. An attacker could leverage this
    vulnerability to leak information. (CVE-2020-26999)

  - Affected applications lack proper validation of user-supplied data when parsing of PAR files. This
    could result in a stack based buffer overflow. An attacker could leverage this vulnerability to execute
    code in the context of the current process. (CVE-2020-27001)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://cert-portal.siemens.com/productcert/pdf/ssa-695540.pdf");
  script_set_attribute(attribute:"solution", value:
"Update JT2Go to version 13.1.0.2 (File version 13.1.0.21083)");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26991");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:siemens:jt2go");
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
  { 'fixed_version': '13.1.0.21083', 'fixed_display':'13.1.0.2 (File version 13.1.0.21083)' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
