#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126468);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/04  6:24:51");

  script_cve_id("CVE-2019-11246");
  script_bugtraq_id(108866);

  script_name(english:"Kubernetes 1.12.x < 1.12.9 / 1.13.x < 1.13.6 / 1.14.x < 1.14.2 kubectl directory traversal");
  script_summary(english:"Checks the version of Kubernetes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application affected by a directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Kubernetes installed on the remote host is a version prior to 1.12.9, or 1.13.x prior to 1.13.6, or
1.14.x prior to 1.14.2. It is, therefore, affected by a directory traversal vulnerability in the kubectl cp command due
to mishandling of symlinks when copying files from a running container. An unauthenticated, remote attacker can exploit
this, by convincing a user to use kubectl cp with a malicious container to overwrite arbitrary files on the remote host.
");
  # https://cloud.google.com/kubernetes-engine/docs/security-bulletins#june-25-2019                                     
  script_set_attribute(attribute:"see_also", value:""); 
  script_set_attribute(attribute:"solution", value:
"Upgrade to Kubernetes 1.12.9, 1.13.6, 1.14.2 or later, please refer to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11246");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/04");

  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kubernetes:kubernetes");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:kubernetes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("kube_detect.nbin");
  script_require_keys("installed_sw/Kubernetes");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('vcf.inc');
include('global_settings.inc');

app_name = 'Kubernetes';
app_info = vcf::get_app_info(app:app_name);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '1.12.0', 'fixed_version' : '1.12.9' },
  { 'min_version' : '1.13.0', 'fixed_version' : '1.13.6' },
  { 'min_version' : '1.14.0', 'fixed_version' : '1.14.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
