
##
# 
##



include('compat.inc');

if (description)
{
  script_id(151666);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/16");

  script_cve_id(
    "CVE-2021-34291",
    "CVE-2021-34292",
    "CVE-2021-34293",
    "CVE-2021-34294",
    "CVE-2021-34295",
    "CVE-2021-34296",
    "CVE-2021-34297",
    "CVE-2021-34298",
    "CVE-2021-34299",
    "CVE-2021-34300",
    "CVE-2021-34301",
    "CVE-2021-34302",
    "CVE-2021-34303",
    "CVE-2021-34304",
    "CVE-2021-34305",
    "CVE-2021-34306",
    "CVE-2021-34307",
    "CVE-2021-34308",
    "CVE-2021-34309",
    "CVE-2021-34310",
    "CVE-2021-34311",
    "CVE-2021-34312",
    "CVE-2021-34313",
    "CVE-2021-34314",
    "CVE-2021-34315",
    "CVE-2021-34316",
    "CVE-2021-34317",
    "CVE-2021-34318",
    "CVE-2021-34319",
    "CVE-2021-34320",
    "CVE-2021-34321",
    "CVE-2021-34322",
    "CVE-2021-34323",
    "CVE-2021-34324",
    "CVE-2021-34325",
    "CVE-2021-34326",
    "CVE-2021-34327",
    "CVE-2021-34328",
    "CVE-2021-34329",
    "CVE-2021-34330",
    "CVE-2021-34331",
    "CVE-2021-34332",
    "CVE-2021-34333"
  );
  script_xref(name:"IAVA", value:"2021-A-0311");

  script_name(english:"Siemens JT2Go < 13.2 Multiple Vulnerabilities (SSA-483182)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Siemens JT2Go installed on the remote Windows hosts is prior to 13.2. It is, therefore, affected by
multiple vulnerabilities, including the following:

  - The Gif_loader.dll library in affected applications lacks proper validation of user-supplied data when
    parsing GIF files. This could result in an out of bounds write past the end of an allocated structure. An
    attacker could leverage this vulnerability to execute code in the context of the current process.
    (CVE-2021-34291)

  - The Tiff_loader.dll library in affected applications lacks proper validation of user-supplied data when
    parsing TIFF files. This could result in an out of bounds read past the end of an allocated buffer. An
    attacker could leverage this vulnerability to execute code in the context of the current process.
    (CVE-2021-34292)

  - The BMP_Loader.dll library in affected applications lacks proper validation of user-supplied data when
    parsing BMP files. This could result in an out of bounds read past the end of an allocated buffer. An
    attacker could leverage this vulnerability to execute code in the context of the current process.
    (CVE-2021-34296)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://cert-portal.siemens.com/productcert/pdf/ssa-483182.pdf");
  script_set_attribute(attribute:"solution", value:
"Update JT2Go to version 13.2 (File version 13.2.0.21165)");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34291");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:siemens:jt2go");
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
  { 'fixed_version': '13.2.0.21165', 'fixed_display':'13.2 (File version 13.2.0.21165)' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
