#
# 
#

include('compat.inc');

if (description)
{
  script_id(138091);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/06");

  script_cve_id("CVE-2020-4449");

  script_name(english:"IBM WebSphere Application Server 7.0.0.x <= 7.0.0.45 / 8.0.0.x <= 8.0.0.15 / 8.5.x < 8.5.5.18 / 9.0.x < 9.0.5.5 Information Disclosure (CVE-2020-4449)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is
version 7.0.0.0 through 7.0.0.45, 8.0.0.0 through 8.0.0.15, 8.5.0.0
through to 8.5.5.17, or 9.0.0.0 through 9.0.5.4. It is, therefore,
affected by an information disclosure vulnerability. An authenticated,
remote attacker can exploit this by sending a specially crafted
sequence of serialized objects to expose sensitive information.");
  script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/181230");
  # https://www.ibm.com/support/pages/node/6220296
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?edd2b9e7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Application Server 8.5.5.18, 9.0.5.5, or later. Alternatively, upgrade
to the minimal fix pack levels required by the interim fix and then apply Interim Fix PH25074.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4449");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
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

fix = 'Interim Fix PH25074';

constraints = [
  {'min_version' : '7.0.0.0', 'max_version' : '7.0.0.45', 'fixed_version' : fix},
  {'min_version' : '8.0.0.0', 'max_version' : '8.0.0.15', 'fixed_version' : fix},
  {'min_version' : '8.5.0.0', 'max_version' : '8.5.5.17', 'fixed_version' : '8.5.5.18 or ' + fix},
  {'min_version' : '9.0.0.0', 'max_version' : '9.0.5.4',  'fixed_version' : '9.0.5.5 or ' + fix}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
