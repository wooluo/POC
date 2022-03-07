#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125879);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/14 11:42:10");

  script_cve_id("CVE-2019-11881");

  script_name(english:"Rancher < 2.2.4 Web Parameter Tampering Vulnerability");
  script_summary(english:"Checks version of Rancher.");

  script_set_attribute(attribute:"synopsis", value:
"A Docker container of Rancher installed on the remote host is
missing a security patch.");
  script_set_attribute(attribute:"description", value:
"The version of a Docker container of Rancher is < 2.2.4 and, thus, is affected by web parameter tampering vulnerability.
A vulnerability exists in the login component, where the errorMsg parameter can be tampered to display arbitrary 
content, filtering tags but not special characters or symbols. There's no other limitation of the message, allowing 
malicious users to lure legitimate users to visit phishing sites with scare tactics, e.g., displaying a 'This version 
of Rancher is outdated, please visit https://malicious.rancher.site/upgrading)' message.

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://github.com/rancher/rancher/issues/20216
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11881");

  script_set_attribute(attribute:"vuln_publication_date",value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date",value:"2019/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");

  script_set_attribute(attribute:"plugin_type",value:"combined");
  script_set_attribute(attribute:"cpe",value:"x-cpe:/a:rancher_labs:rancher");
  script_set_attribute(attribute:"potential_vulnerability",value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("rancher_local_detection.nbin", "rancher_web_ui_detect.nbin");
  script_require_keys("installed_sw/Rancher", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app = 'Rancher';

get_install_count(app_name:app, exit_if_zero:TRUE);
app_info = vcf::combined_get_app_info(app:app);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  {'fixed_version' : '2.2.4'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
