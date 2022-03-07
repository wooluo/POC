
##
# 
##


include('compat.inc');

if (description)
{
  script_id(152220);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/05");

  script_cve_id(
    "CVE-2021-21831",
    "CVE-2021-21870",
    "CVE-2021-21893",
    "CVE-2021-34831",
    "CVE-2021-34832",
    "CVE-2021-34833",
    "CVE-2021-34834",
    "CVE-2021-34835",
    "CVE-2021-34836",
    "CVE-2021-34837",
    "CVE-2021-34838",
    "CVE-2021-34839",
    "CVE-2021-34840",
    "CVE-2021-34841",
    "CVE-2021-34842",
    "CVE-2021-34843",
    "CVE-2021-34844",
    "CVE-2021-34845",
    "CVE-2021-34846",
    "CVE-2021-34847",
    "CVE-2021-34848",
    "CVE-2021-34849",
    "CVE-2021-34850",
    "CVE-2021-34851",
    "CVE-2021-34852",
    "CVE-2021-34853"
  );
  script_xref(name:"IAVA", value:"2021-A-0357");

  script_name(english:"Foxit PDF Editor (PhantomPDF) < 11.0.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Editor application (formally known as PhantomPDF) installed on the remote
Windows host is prior to 11.0.1. It is, therefore affected by multiple vulnerabilities:

  - Multiple remote code execution vulnerabilities exist in Foxit PDF Editor due to a use-after-free error
    when handling certain Javascripts and annotation objects. An unauthenticated, remote attacker can exploit
    these, by convincing a user to open a malicious document, to execute arbitrary code in the context of the
    current user. (CVE-2021-21831, CVE-2021-21870, CVE-2021-34831, CVE-2021-34832, CVE-2021-34847,
    CVE-2021-34848, CVE-2021-34849, CVE-2021-34850)

  - Multiple remote code execution vulnerabilities exist in Foxit PDF Editor due to a use-after-free error
    when handling the annotation objects in certain PDF files if the same annotation dictionary is referenced
    in the page structures for different pages. An unauthenticated, remote attacker can exploit these, by
    convincing a user to open a malicious document, to execute arbitrary code in the context of the current
    user. (CVE-2021-34833, CVE-2021-34834, CVE-2021-34835, CVE-2021-34836, CVE-2021-34837, CVE-2021-34838,
    CVE-2021-34839, CVE-2021-34840, CVE-2021-34841, CVE-2021-34842, CVE-2021-34843, CVE-2021-34844,
    CVE-2021-34845, CVE-2021-34851, CVE-2021-34852, CVE-2021-34853)

  - A remote code execution vulnerability exists in Foxit PDF Editor due to a use-after-free error when
    handling certain events of form elements. An unauthenticated, remote attacker can exploit these, by
    convincing a user to open a malicious document, to execute arbitrary code in the context of the current
    user. (CVE-2021-21893)

  - A remote code execution vulnerability exists in Foxit PDF Editor due to a use-after-free errror when
    traversing bookmark nodes in certain PDF files. An unauthenticated, remote attacker can exploit these, by
    convincing a user to open a malicious document, to execute arbitrary code in the context of the current
    user. (CVE-2021-34846)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Editor version 11.0.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21831");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit("SMB/Registry/Enumerated");

var app = 'FoxitPhantomPDF';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'max_version' : '10.1.4.37651', 'fixed_version' : '11.0.1' },
  { 'min_version' : '11.0', 'max_version' : '11.0.0.49893', 'fixed_version' : '11.0.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
