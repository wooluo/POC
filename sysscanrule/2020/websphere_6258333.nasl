#
# 
#

include('compat.inc');

if (description)
{
  script_id(139871);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/28");

  script_cve_id("CVE-2020-4589");

  script_name(english:"IBM WebSphere Application Server 7.0.0.x <= 7.0.0.45 / 8.0.0.x <= 8.0.0.15 / 8.5.x < 8.5.5.17 / 9.0.x < 9.0.5.4 RCE (6258333)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is
version 7.0.0.0 through 7.0.0.45, 8.0.0.0 through 8.0.0.15, 8.5.0.0
through to 8.5.5.17, or 9.0.0.0 through 9.0.5.4. It is, therefore,
affected by an remote code execution vulnerability. An authenticated,
remote attacker can exploit this by sending a specially crafted
sequence of serialized objects from untrusted source.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6258333");
  # https://exchange.xforce.ibmcloud.com/vulnerabilities/184585
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d300524");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Application Server 8.5.5.18, 9.0.5.5, or later. Alternatively, upgrade
to the minimal fix pack levels required by the interim fix and then apply Interim Fix PH27414.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-45899");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl", "ibm_enum_products.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}

include('vcf.inc');
include('http.inc');

app = 'IBM WebSphere Application Server';
fix = 'Interim Fix PH27414';

get_install_count(app_name:app, exit_if_zero:TRUE);
app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

# If the detection is only remote, Source will be set, and we should require paranoia
if (!empty_or_null(app_info['Source']) && report_paranoia < 2)
  audit(AUDIT_PARANOID);

constraints = [
  {'min_version' : '7.0.0.0', 'max_version' : '7.0.0.45', 'fixed_version' : fix},
  {'min_version' : '8.0.0.0', 'max_version' : '8.0.0.15', 'fixed_version' : fix},
  {'min_version' : '8.5.0.0', 'max_version' : '8.5.5.17', 'fixed_version' : '8.5.5.18 or ' + fix},
  {'min_version' : '9.0.0.0', 'max_version' : '9.0.5.4',  'fixed_version' : '9.0.5.5 or ' + fix}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

