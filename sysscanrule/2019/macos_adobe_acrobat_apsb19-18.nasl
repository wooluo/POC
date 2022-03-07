#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125219);
  script_version("1.3");
  script_cvs_date("Date: 2019/05/30 16:25:06");

  script_cve_id(
    "CVE-2019-7140",
    "CVE-2019-7141",
    "CVE-2019-7142",
    "CVE-2019-7143",
    "CVE-2019-7144",
    "CVE-2019-7145",
    "CVE-2019-7758",
    "CVE-2019-7759",
    "CVE-2019-7760",
    "CVE-2019-7761",
    "CVE-2019-7762",
    "CVE-2019-7763",
    "CVE-2019-7764",
    "CVE-2019-7765",
    "CVE-2019-7766",
    "CVE-2019-7767",
    "CVE-2019-7768",
    "CVE-2019-7769",
    "CVE-2019-7770",
    "CVE-2019-7771",
    "CVE-2019-7772",
    "CVE-2019-7773",
    "CVE-2019-7774",
    "CVE-2019-7775",
    "CVE-2019-7776",
    "CVE-2019-7777",
    "CVE-2019-7778",
    "CVE-2019-7779",
    "CVE-2019-7780",
    "CVE-2019-7781",
    "CVE-2019-7782",
    "CVE-2019-7783",
    "CVE-2019-7784",
    "CVE-2019-7785",
    "CVE-2019-7786",
    "CVE-2019-7787",
    "CVE-2019-7788",
    "CVE-2019-7789",
    "CVE-2019-7790",
    "CVE-2019-7791",
    "CVE-2019-7792",
    "CVE-2019-7793",
    "CVE-2019-7794",
    "CVE-2019-7795",
    "CVE-2019-7796",
    "CVE-2019-7797",
    "CVE-2019-7798",
    "CVE-2019-7799",
    "CVE-2019-7800",
    "CVE-2019-7801",
    "CVE-2019-7802",
    "CVE-2019-7803",
    "CVE-2019-7804",
    "CVE-2019-7805",
    "CVE-2019-7806",
    "CVE-2019-7807",
    "CVE-2019-7808",
    "CVE-2019-7809",
    "CVE-2019-7810",
    "CVE-2019-7811",
    "CVE-2019-7812",
    "CVE-2019-7813",
    "CVE-2019-7814",
    "CVE-2019-7817",
    "CVE-2019-7818",
    "CVE-2019-7820",
    "CVE-2019-7821",
    "CVE-2019-7822",
    "CVE-2019-7823",
    "CVE-2019-7824",
    "CVE-2019-7825",
    "CVE-2019-7826",
    "CVE-2019-7827",
    "CVE-2019-7828",
    "CVE-2019-7829",
    "CVE-2019-7830",
    "CVE-2019-7831",
    "CVE-2019-7832",
    "CVE-2019-7833",
    "CVE-2019-7834",
    "CVE-2019-7835",
    "CVE-2019-7836",
    "CVE-2019-7841"
  );

  script_name(english:"Adobe Acrobat <= 2015.006.30495 / 2017.011.30140 / 2019.010.20100 Multiple Vulnerabilities (APSB19-18) (macOS)");
  script_summary(english:"Checks the version of Adobe Acrobat.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote macOS host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote macOS host is a
version prior or equal to 2015.006.30495, 2017.011.30140, or
2019.010.20100. It is, therefore, affected by multiple
vulnerabilities.

  - Out-of-Bounds Read potentially leading to Information
    Disclosure (CVE-2019-7841, CVE-2019-7836, CVE-2019-7826,
    CVE-2019-7813, CVE-2019-7812, CVE-2019-7811,
    CVE-2019-7810, CVE-2019-7803, CVE-2019-7802,
    CVE-2019-7801, CVE-2019-7799, CVE-2019-7798,
    CVE-2019-7795, CVE-2019-7794, CVE-2019-7793,
    CVE-2019-7790, CVE-2019-7789, CVE-2019-7787,
    CVE-2019-7780, CVE-2019-7778, CVE-2019-7777,
    CVE-2019-7776, CVE-2019-7775, CVE-2019-7774,
    CVE-2019-7773, CVE-2019-7771, CVE-2019-7770,
    CVE-2019-7769, CVE-2019-7758, CVE-2019-7145,
    CVE-2019-7144, CVE-2019-7143, CVE-2019-7142,
    CVE-2019-7141, CVE-2019-7140)

  - Out-of-Bounds Write potentially leading to Arbitrary
    Code Execution (CVE-2019-7829, CVE-2019-7825,
    CVE-2019-7822, CVE-2019-7818, CVE-2019-7804,
    CVE-2019-7800)

  - Type Confusion potentially leading to Arbitrary Code
    Execution (CVE-2019-7820)

  - Use After Free potentially leading to Arbitrary Code
    Execution (CVE-2019-7835, CVE-2019-7834, CVE-2019-7833,
    CVE-2019-7832, CVE-2019-7831, CVE-2019-7830,
    CVE-2019-7823, CVE-2019-7821, CVE-2019-7817,
    CVE-2019-7814, CVE-2019-7809, CVE-2019-7808,
    CVE-2019-7807, CVE-2019-7806, CVE-2019-7805,
    CVE-2019-7797, CVE-2019-7796, CVE-2019-7792,
    CVE-2019-7791, CVE-2019-7788, CVE-2019-7786,
    CVE-2019-7785, CVE-2019-7783, CVE-2019-7782,
    CVE-2019-7781, CVE-2019-7772, CVE-2019-7768,
    CVE-2019-7767, CVE-2019-7766, CVE-2019-7765,
    CVE-2019-7764, CVE-2019-7763, CVE-2019-7762,
    CVE-2019-7761, CVE-2019-7760, CVE-2019-7759)

  - Heap Overflow potentially leading to Arbitrary Code
    Execution (CVE-2019-7828, CVE-2019-7827)

  - Buffer Error potentially leading to Arbitrary Code
    Execution (CVE-2019-7824)

  - Double Free potentially leading to Arbitrary Code
    Execution (CVE-2019-7784)

  - Security Bypass potentially leading to Arbitrary Code
    Execution (CVE-2019-7779)

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb19-18.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 2015.006.30497 or 2017.011.30142 or
2019.012.20034 or later.");
  script_set_attribute(attribute:"risk_factor", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_acrobat_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Acrobat");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
os = get_kb_item("Host/MacOSX/Version");
if (empty_or_null(os)) audit(AUDIT_OS_NOT, "Mac OS X");

app_info = vcf::get_app_info(app:"Adobe Acrobat");

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
constraints = [
  { "min_version" : "15.6", "max_version" : "15.006.30495", "fixed_version" : "15.006.30497" },
  { "min_version" : "17.8", "max_version" : "17.011.30140", "fixed_version" : "17.011.30142" },
  { "min_version" : "15.7", "max_version" : "19.010.20100", "fixed_version" : "19.012.20034" }
];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
