#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127046);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:39");

  script_cve_id(
    "CVE-2019-8644",
    "CVE-2019-8649",
    "CVE-2019-8658",
    "CVE-2019-8666",
    "CVE-2019-8669",
    "CVE-2019-8671",
    "CVE-2019-8672",
    "CVE-2019-8673",
    "CVE-2019-8676",
    "CVE-2019-8677",
    "CVE-2019-8678",
    "CVE-2019-8679",
    "CVE-2019-8680",
    "CVE-2019-8681",
    "CVE-2019-8683",
    "CVE-2019-8684",
    "CVE-2019-8685",
    "CVE-2019-8686",
    "CVE-2019-8687",
    "CVE-2019-8688",
    "CVE-2019-8689",
    "CVE-2019-8690",
    "CVE-2019-13118"
  );
  script_bugtraq_id(109328, 109329);
  script_xref(name:"APPLE-SA", value:"HT210356");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-07-17");

  script_name(english:"Apple iTunes < 12.9.6 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks the version of iTunes on Windows");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
prior to 12.9.6. It is, therefore, affected by multiple
vulnerabilities as referenced in the HT210356 advisory.

  - A remote attacker may be able to view sensitive
    information (CVE-2019-13118)

  - Processing maliciously crafted web content may lead to
    universal cross site scripting (CVE-2019-8658,
    CVE-2019-8690, CVE-2019-8649)

  - Processing maliciously crafted web content may lead to
    arbitrary code execution (CVE-2019-8644, CVE-2019-8666,
    CVE-2019-8669, CVE-2019-8671, CVE-2019-8672,
    CVE-2019-8673, CVE-2019-8676, CVE-2019-8677,
    CVE-2019-8678, CVE-2019-8679, CVE-2019-8680,
    CVE-2019-8681, CVE-2019-8683, CVE-2019-8684,
    CVE-2019-8685, CVE-2019-8686, CVE-2019-8687,
    CVE-2019-8688, CVE-2019-8689)

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210356");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.9.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8689");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/26");

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

constraints = [{'fixed_version':'12.9.6'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
