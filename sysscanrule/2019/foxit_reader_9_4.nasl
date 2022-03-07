#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121046);
  script_version("1.5");
  script_cvs_date("Date: 2019/06/06 15:40:15");

  script_cve_id(
    "CVE-2018-3956",
    "CVE-2018-18688",
    "CVE-2018-18689",
    "CVE-2019-5005",
    "CVE-2019-5006",
    "CVE-2019-5007",
    "CVE-2019-6727",
    "CVE-2019-6728",
    "CVE-2019-6729",
    "CVE-2019-6730",
    "CVE-2019-6731",
    "CVE-2019-6732",
    "CVE-2019-6733",
    "CVE-2019-6734",
    "CVE-2019-6735"
  );
  script_bugtraq_id(
    106798,
    107496,
    107552
  );

  script_name(english:"Foxit Reader < 9.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit Reader.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",  value:
"The version of Foxit Reader installed on the remote Windows host is
prior to 9.4. It is, therefore, affected by multiple vulnerabilities:

  - An out-of-bounds read/write vulnerability and crash
    when handling XFA element attributes. (CVE-2018-3956)

  - A signature validation bypass vulnerability which
    could lead to incorrect validation results.
    (CVE-2018-18688, CVE-2018-18689)

  - Flaws in how PDF files are processed/handled could
    lead to arbitrary code execution. An attacker can 
    exploit this by convincing a user to open a specially
    crafted file in order to cause the execution of arbitrary
    code. (CVE-2019-6728,CVE-2019-6729)

Additionally, the application was affected by multiple potential 
information disclosure, denial of service, and remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 9.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6729");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader");

  exit(0);
}

include('vcf.inc');

app = 'Foxit Reader';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [{
  'min_version' : '9.0',
  'max_version' : '9.3.0.10826',
  'fixed_version' : '9.4'
  }];
  
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
