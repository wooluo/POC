#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126475);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/11 12:05:36");

  script_cve_id(
    "CVE-2019-6237",
    "CVE-2019-8571",
    "CVE-2019-8577",
    "CVE-2019-8583",
    "CVE-2019-8584",
    "CVE-2019-8586",
    "CVE-2019-8587",
    "CVE-2019-8594",
    "CVE-2019-8595",
    "CVE-2019-8596",
    "CVE-2019-8597",
    "CVE-2019-8598",
    "CVE-2019-8600",
    "CVE-2019-8601",
    "CVE-2019-8602",
    "CVE-2019-8607",
    "CVE-2019-8608",
    "CVE-2019-8609",
    "CVE-2019-8610",
    "CVE-2019-8611",
    "CVE-2019-8615",
    "CVE-2019-8619",
    "CVE-2019-8622",
    "CVE-2019-8623",
    "CVE-2019-8628"
  );
  script_bugtraq_id(108491, 108497);
  script_xref(name:"APPLE-SA", value:"HT210124");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-05-09");

  script_name(english:"Apple iTunes for Windows < 12.9.5 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks the version of iTunes for Windows on Windows");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes for Windows installed on the remote
Windows host is prior to 12.9.5. It is, therefore, affected by
multiple vulnerabilities as referenced in the HT210124 advisory.

  - An application may be able to gain elevated privileges
    (CVE-2019-8577)

  - A maliciously crafted SQL query may lead to arbitrary
    code execution (CVE-2019-8600)

  - A malicious application may be able to read restricted
    memory (CVE-2019-8598)

  - A malicious application may be able to elevate
    privileges (CVE-2019-8602)

  - Processing maliciously crafted web content may result in
    the disclosure of process memory (CVE-2019-8607)

  - Processing maliciously crafted web content may lead to
    arbitrary code execution (CVE-2019-6237, CVE-2019-8571,
    CVE-2019-8583, CVE-2019-8584, CVE-2019-8586,
    CVE-2019-8587, CVE-2019-8594, CVE-2019-8595,
    CVE-2019-8596, CVE-2019-8597, CVE-2019-8601,
    CVE-2019-8608, CVE-2019-8609, CVE-2019-8610,
    CVE-2019-8611, CVE-2019-8615, CVE-2019-8619,
    CVE-2019-8622, CVE-2019-8623, CVE-2019-8628)

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210124");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes for Windows version 12.9.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8628");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");


  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("itunes_sharing.nasl");
  script_require_keys("installed_sw/iTunes DAAP");
  script_require_ports("Services/www", 3689);

  exit(0);
}
include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('vcf.inc');

app = 'iTunes DAAP';
port = get_http_port(default:3689, ignore_broken:TRUE);

app_info = vcf::get_app_info(app:app, port:port);
if (app_info.Type != 'Windows') audit(AUDIT_OS_NOT, 'Windows');
constraints = [{'fixed_version':'12.9.5'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
