##
# 
##
include('compat.inc');

if (description)
{
  script_id(148923);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/22");

  script_cve_id("CVE-2020-25649", "CVE-2021-2277");

  script_name(english:"Oracle Coherence (Apr 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of the Oracle Coherence installed on the remote host is missing a critical patch update. It is, therefore, affected by
a vulnerability, as referenced in the April 2021 CPU advisory.

  - Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Core 
  (jackson-databind)). Supported versions that are affected are 12.2.1.4.0 and 14.1.1.0.0. Easily 
  exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise 
  Oracle Coherence. Successful attacks of this vulnerability can result in unauthorized creation, 
  deletion or modification access to critical data or all Oracle Coherence accessible data (CVE-2020-25649).

  - Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Core). Supported 
  versions that are affected are 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily 
  exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise 
  Oracle Coherence. Successful attacks of this vulnerability can result in unauthorized access to critical
  data or complete access to all Oracle Coherence accessible data (CVE-2021-2277). 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25649");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:coherence");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_coherence_installed.nbin");
  script_require_keys("installed_sw/Oracle Coherence");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Coherence');

var constraints = [
  { 'min_version' : '3.7.1.0', 'fixed_version' : '3.7.1.21' },
  { 'min_version' : '12.1.3.0.0', 'fixed_version' : '12.1.3.0.11' },
  { 'min_version' : '12.2.1.3.0', 'fixed_version' : '12.2.1.3.13' },
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.8' },
  { 'min_version' : '14.1.1.0.0', 'fixed_version' : '14.1.1.0.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
