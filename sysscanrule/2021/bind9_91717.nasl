
##
# 
##


include('compat.inc');

if (description)
{
  script_id(152682);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/19");

  script_cve_id("CVE-2021-25218");

  script_name(english:"ISC BIND 9.16.19 / 9.16.19-S1 / 9.17.16 Assertion Failure (CVE-2021-25218)");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by an assertion failure vulnerability vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ISC BIND installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the CVE-2021-25218 advisory.

  - In BIND 9.16.19, 9.17.16. Also, version 9.16.19-S1 of BIND Supported Preview Edition When a vulnerable
    version of named receives a query under the circumstances described above, the named process will
    terminate due to a failed assertion check. The vulnerability affects only BIND 9 releases 9.16.19,
    9.17.16, and release 9.16.19-S1 of the BIND Supported Preview Edition. (CVE-2021-25218)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/v1/docs/CVE-2021-25218");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ISC BIND version 9.16.20 / 9.17.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25218");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::bind::initialize();

var app_info = vcf::get_app_info(app:'BIND', port:53, kb_ver:'bind/version', service:TRUE, proto:'UDP');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var constraints = [
  { 'equal' : '9.16.19', 'fixed_version' : '9.16.20' },
  { 'equal' : '9.16.19-S1', 'fixed_version' : '9.16.20-S1' },
  { 'equal' : '9.17.16', 'fixed_version' : '9.17.17' }
];
constraints = vcf::bind::filter_constraints(constraints:constraints, version:app_info.version);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
