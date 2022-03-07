#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125738);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/28 10:05:53");

  script_cve_id("CVE-2019-6469");
  script_bugtraq_id(108517);

  script_name(english:"ISC BIND 9.10.5-S1 <= 9.11.6-S1 EDNS Client Subnet RRSIG Denial of Service");
  script_summary(english:"Checks the version of ISC BIND.");
  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ISC BIND Supported Preview Edition running on the
remote host is version 9.10.5-S1 through 9.11.6-S1. It is, therefore,
affected by an error related to handling RRSIG data that allows an
attacker to crash the application if the EDNS Client Subnet (ECS)
feature is enabled.");
  # https://kb.isc.org/docs/cve-2019-6469
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ISC BIND version 9.11.7-S1 or later.");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6469");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

vcf::bind::initialize();

app_info = vcf::get_app_info(app:'BIND', port:53, kb_ver:'bind/version', service:TRUE, proto:'UDP');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  { 'min_version' : '9.10.5-S1', 'max_version' : '9.11.6-S1' , 'fixed_display' : '9.11.7-S1'}
];
constraints = vcf::bind::filter_constraints(constraints:constraints, version:app_info.version);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
