#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127899);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/16 11:53:22");

  script_cve_id(
    "CVE-2019-7968",
    "CVE-2019-7969",
    "CVE-2019-7970",
    "CVE-2019-7971",
    "CVE-2019-7972",
    "CVE-2019-7973",
    "CVE-2019-7974",
    "CVE-2019-7975",
    "CVE-2019-7976",
    "CVE-2019-7977",
    "CVE-2019-7978",
    "CVE-2019-7979",
    "CVE-2019-7980",
    "CVE-2019-7981",
    "CVE-2019-7982",
    "CVE-2019-7983",
    "CVE-2019-7984",
    "CVE-2019-7985",
    "CVE-2019-7986",
    "CVE-2019-7987",
    "CVE-2019-7988",
    "CVE-2019-7989",
    "CVE-2019-7990",
    "CVE-2019-7991",
    "CVE-2019-7992",
    "CVE-2019-7993",
    "CVE-2019-7994",
    "CVE-2019-7995",
    "CVE-2019-7996",
    "CVE-2019-7997",
    "CVE-2019-7998",
    "CVE-2019-7999",
    "CVE-2019-8000",
    "CVE-2019-8001"
  );
  script_xref(name:"IAVA", value:"2019-A-0297");

  script_name(english:"Adobe Photoshop CC 19.x <= 19.1.8 / 20.x <= 20.0.5 Vulnerability (APSB19-44)");
  script_summary(english:"Checks the version of Adobe Photoshop.");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Photoshop installed on remote Windows host is affected by a
vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop CC installed on the remote Windows host
is equal or prior to 19.1.8 (2018.1.8), 20.0.5 (2019.0.5). It is, therefore,
affected by the vulnerabilities as referenced in the apsb19-44 advisory.

  - An heap-overflow flaw exists that allows remote attackers
    to execute arbitrary commands via unspecified means.
    (CVE-2019-7978, CVE-2019-7980, CVE-2019-7985,
    CVE-2019-7990, CVE-2019-7993)

  - A type-confusion flaw exists that allows remote attackers
    to execute arbitrary commands via unspecified means.
    (CVE-2019-7969, CVE-2019-7970, CVE-2019-7971,
    CVE-2019-7972, CVE-2019-7973, CVE-2019-7974,
    CVE-2019-7975)

  - An out-of-bounds read flaw exists that allows remote attackers
    to execute arbitrary commands via unspecified means.
    (CVE-2019-7977, CVE-2019-7981, CVE-2019-7987,
    CVE-2019-7991, CVE-2019-7992, CVE-2019-7995,
    CVE-2019-7996, CVE-2019-7997, CVE-2019-7998,
    CVE-2019-7999, CVE-2019-8000, CVE-2019-8001)

  - A command injection flaw exists that allows remote attackers
    to execute arbitrary commands via unspecified means.
    (CVE-2019-7968, CVE-2019-7989)

  - An out-of-bounds write flaw exists that allows remote attackers
    to execute arbitrary commands via unspecified means.
    (CVE-2019-7976, CVE-2019-7979, CVE-2019-7982,
    CVE-2019-7983, CVE-2019-7984, CVE-2019-7986,
    CVE-2019-7988, CVE-2019-7994)

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb19-44.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop CC version 19.1.9 (2018.1.9), 20.0.6
(2019.0.6) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7978");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop_cc");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_photoshop_installed.nasl");
  script_require_keys("installed_sw/Adobe Photoshop", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe Photoshop', win_local:TRUE);

if ('CC' >!< app_info.Product) vcf::vcf_exit(0, 'Only Adobe Photoshop CC is affected.');
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '19', 'max_version' : '19.1.8', 'fixed_version' : '19.1.9' },
  { 'min_version' : '20', 'max_version' : '20.0.5', 'fixed_version' : '20.0.6' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
