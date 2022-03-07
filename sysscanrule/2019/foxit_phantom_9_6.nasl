#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126750);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/26 16:36:28");

  script_cve_id(
    "CVE-2019-6776",
    "CVE-2019-13316",
    "CVE-2019-13317",
    "CVE-2019-14207",
    "CVE-2019-14211",
    "CVE-2019-14212",
    "CVE-2019-14213"
  );
  script_xref(name:"ZDI", value:"ZDI-19-631");
  script_xref(name:"ZDI", value:"ZDI-19-633");
  script_xref(name:"ZDI", value:"ZDI-19-634");
  script_xref(name:"IAVA", value:"2019-A-0265");

  script_name(english:"Foxit PhantomPDF < 9.6 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by  multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PhantomPDF application (formally known as Phantom) installed on the remote Windows
host is prior to 9.6. It is, therefore affected by  multiple vulnerabilities: Note that GizaNE has not tested for this
issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 9.6 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13317");
  # https://www.foxitsoftware.com/support/security-bulletins.php
  script_set_attribute(attribute:"see_also", value:"");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF");

  exit(0);
}

include('vcf.inc');

app = 'FoxitPhantomPDF';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '9.0', 'max_version' : '9.5.0.20723', 'fixed_version' : '9.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
