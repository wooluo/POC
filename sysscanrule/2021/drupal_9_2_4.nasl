
##
# 
##


include('compat.inc');

if (description)
{
  script_id(152533);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/20");

  script_cve_id("CVE-2021-32808", "CVE-2021-32809", "CVE-2021-37695");
  script_xref(name:"IAVA", value:"2021-A-0384");

  script_name(english:"Drupal 8.9.x < 8.9.18 / 9.1.x < 9.1.12 / 9.2.x < 9.2.4 Multiple Vulnerabilities (SA-CORE-2021-005)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 8.9.x prior to
8.9.18, 9.1.x prior to 9.1.12, or 9.2.x prior to 9.2.4. It is, therefore, affected by a multiple vulnerabilities due to
its usage of a third party component, CKEditor, for WYSIWYG editing:

  - A vulnerability was discovered in CKEditor 4 Fake Objects package. The vulnerability allowed to inject
    malformed Fake Objects HTML, which could result in executing JavaScript code. (CVE-2021-37695)

  - A vulnerability was discovered in the clipboard Widget plugin if used alongside the undo feature. The
    vulnerability allows a user to abuse undo functionality using malformed widget HTML, which could result
    in executing JavaScript code. (CVE-2021-32808)

  - A vulnerability was discovered in CKEditor 4 Clipboard package. The vulnerability allowed to abuse paste 
    functionality using malformed HTML, which could result in injecting arbitrary HTML into the editor. (CVE-2021-32809)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2021-005");
  # https://ckeditor.com/blog/ckeditor-4.16.2-with-browser-improvements-and-security-fixes/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03aa81e2");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ckeditor/ckeditor4");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.9.18");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.1.12");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.2.4");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2011-002");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/steward");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 8.9.18 / 9.1.12 / 9.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}
include('http.inc');
include('vcf.inc');

if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

var port = get_http_port(default:80, php:TRUE);
var app_info = vcf::get_app_info(app:'Drupal', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  {'min_version': '8.9', 'fixed_version': '8.9.18'},
  {'min_version': '9.1', 'fixed_version': '9.1.12'},
  {'min_version': '9.2', 'fixed_version': '9.2.4'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE,
  flags:{'xss':TRUE}
);
