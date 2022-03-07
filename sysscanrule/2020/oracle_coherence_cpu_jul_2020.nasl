#
# 
#

include('compat.inc');

if (description)
{
  script_id(138563);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/17");

  script_cve_id("CVE-2020-14642");
  script_xref(name:"IAVA", value:"2020-A-0327");

  script_name(english:"Oracle Coherence (July 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Oracle Coherence installed on the remote host is missing a critical patch update. It is, therefore, affected by
 a vulnerability, as referenced in the July 2020 Oracle CPU advisory.

  - Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: CacheStore). Supported versions
  that are affected are 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability
  allows unauthenticated attacker with network access via HTTP to compromise Oracle Coherence. Successful attacks of this
  vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of
  Oracle Coherence.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14642");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:coherence");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_coherence_installed.nbin");
  script_require_keys("installed_sw/Oracle Coherence");

  exit(0);
}

include('vcf.inc');

app_name = 'Oracle Coherence';

app_info = vcf::get_app_info(app:app_name);
 
constraints = [
  { 'min_version' : '3.7.1.0', 'fixed_version' : '3.7.1.19' },
  { 'min_version' : '12.1.3.0.0', 'fixed_version' : '12.1.3.0.9' },
  { 'min_version' : '12.2.1.3.0', 'fixed_version' : '12.2.1.3.10' },
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.5' },
  { 'min_version' : '14.1.1.0.0', 'fixed_version' : '14.1.1.0.1' }
];
 
vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
