#
# 
#


include('compat.inc');

if (description)
{
  script_id(149786);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/21");

  script_cve_id("CVE-2021-21984");
  script_xref(name:"VMSA", value:"2021-0007");

  script_name(english:"VMware vRealize Business for Cloud RCE (VMSA-2021-0007)");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware vRealize Business for Cloud host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vRealize Business for Cloud running on the remote host is 7.6.x prior to 7.6.0.46000-17828140.
It is, therefore, affected by a remote code execution (RCE) vulnerability due to an unauthorized end point. A malicious
actor with network access may exploit this issue causing unauthorized remote code execution on vRealize Business for
Cloud Virtual Appliance.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2021-0007.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 7.6.0 Build 17828140 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21984");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_business_for_cloud");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/VMware vRealize Business for Cloud/Version", "Host/VMware vRealize Business for Cloud/Build", "Host/VMware vRealize Business for Cloud/VerUI");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::vmware_vrealize::get_app_info();

var constraints = [
  { 'min_version' : '7.6.0.0', 'fixed_version' : '7.6.0.17828140', 'fixed_display': '7.6.0 Build 17828140'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
