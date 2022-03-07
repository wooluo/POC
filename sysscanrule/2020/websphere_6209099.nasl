#
# 
#

include('compat.inc');

if (description)
{
  script_id(139065);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/30");

  script_cve_id("CVE-2020-4365");
  script_xref(name:"IAVA", value:"2020-A-0254-S");

  script_name(english:"IBM WebSphere Application Server 8.5.x < 8.5.5.18 Server-side Request Forgery (6209099)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a server-side request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is version 8.5.x prior to 8.5.5.18. It is, therefore,
affected by a server-side request forgery vulnerability. An authenticated, remote attacker can exploit this, by sending
a specially crafted request, to obtain sensitive data.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6209099");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Application Server 8.5.5.18, or later. Alternatively, upgrade to the minimal fix pack level
required by the interim fix and then apply Interim Fix PH23638.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4365");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl");
  script_require_keys("www/WebSphere", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8880, 8881, 9001);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'IBM WebSphere Application Server';

port = get_http_port(default:8880, embedded:FALSE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:4);

fix = 'Interim Fix PH23638';

constraints = [
  { 'min_version' : '8.5.0.0', 'max_version' : '8.5.5.17', 'fixed_version' : '8.5.5.18 or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
