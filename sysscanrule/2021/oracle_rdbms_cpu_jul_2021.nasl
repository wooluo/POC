
##
# 
##

include('compat.inc');

if (description)
{
  script_id(152026);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/23");

  script_cve_id(
    "CVE-2018-21010",
    "CVE-2019-12415",
    "CVE-2019-12973",
    "CVE-2019-17545",
    "CVE-2019-17566",
    "CVE-2020-7760",
    "CVE-2020-8908",
    "CVE-2020-10543",
    "CVE-2020-10878",
    "CVE-2020-11987",
    "CVE-2020-11988",
    "CVE-2020-12723",
    "CVE-2020-13956",
    "CVE-2020-15389",
    "CVE-2020-25649",
    "CVE-2020-25649",
    "CVE-2020-26870",
    "CVE-2020-27193",
    "CVE-2020-27814",
    "CVE-2020-27841",
    "CVE-2020-27842",
    "CVE-2020-27843",
    "CVE-2020-27844",
    "CVE-2020-27845",
    "CVE-2020-28196",
    "CVE-2021-2326",
    "CVE-2021-2328",
    "CVE-2021-2329",
    "CVE-2021-2330",
    "CVE-2021-2333",
    "CVE-2021-2334",
    "CVE-2021-2335",
    "CVE-2021-2336",
    "CVE-2021-2337",
    "CVE-2021-2351",
    "CVE-2021-2438",
    "CVE-2021-2460",
    "CVE-2021-23336"
  );
  script_xref(name:"IAVA", value:"2021-A-0330");
  
  script_name(english:"Oracle Database Server Multiple Vulnerabilities (Jul 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a database server which is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Database Server installed on the remote host are affected by multiple vulnerabilities as
referenced in the July 2021 CPU advisory.

  - Vulnerability in the Advanced Networking Option component of Oracle Database Server. Supported versions 
  that are affected are 12.1.0.2 and 19c. Difficult to exploit vulnerability allows unauthenticated attacker 
  with network access via Oracle Net to compromise Advanced Networking Option. Successful attacks require 
  human interaction from a person other than the attacker and while the vulnerability is in Advanced 
  Networking Option, attacks may significantly impact additional products. Successful attacks of this 
  vulnerability can result in takeover of Advanced Networking Option. (CVE-2021-2351)

  - Vulnerability in the Oracle Text component of Oracle Database Server. Supported versions that are affected
  are 12.1.0.2 and 19c. Easily exploitable vulnerability allows high privileged attacker having Create Any 
  Procedure, Alter Any Table privilege with network access via Oracle Net to compromise Oracle Text. Successful
  attacks of this vulnerability can result in takeover of Oracle Text. (CVE-2021-2328)

  - Vulnerability in the Oracle XML DB component of Oracle Database Server. Supported versions that are affected
  are 12.1.0.2 and 19c. Easily exploitable vulnerability allows high privileged attacker having Create Any 
  Procedure, Create Public Synonym privilege with network access via Oracle Net to compromise Oracle XML DB. 
  Successful attacks of this vulnerability can result in takeover of Oracle XML DB. (CVE-2021-2329)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2351");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_rdbms::get_app_info();

var constraints = [
  # RDBMS:
  {'min_version': '19.0', 'fixed_version': '19.10.3.0.210720', 'missing_patch':'32923627', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.12.0.0.210720', 'missing_patch':'32832237', 'os':'win', 'component':'db'},
  {'min_version': '19.11', 'fixed_version': '19.11.1.0.210720', 'missing_patch':'32844504', 'os':'unix', 'component':'db'},
  {'min_version': '19.12', 'fixed_version': '19.12.0.0.210720', 'missing_patch':'32904851', 'os':'unix', 'component':'db'},
 
  {'min_version': '12.2.0.1.0', 'fixed_version': '12.2.0.1.210720', 'missing_patch':'32916808', 'os':'unix', 'component':'db'},
  {'min_version': '12.2.0.1.0', 'fixed_version': '12.2.0.1.210720', 'missing_patch':'32775037', 'os':'win', 'component':'db'},

  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.210720', 'missing_patch':'32768233, 32917362', 'os':'unix', 'component':'db'},
  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.210720', 'missing_patch':'32774982', 'os':'win', 'component':'db'},
  
  # OJVM:
  {'min_version': '19.0',  'fixed_version': '19.12.0.0.210720', 'missing_patch':'32876380', 'os':'unix', 'component':'ojvm'},
  {'min_version': '19.0',  'fixed_version': '19.12.0.0.210720', 'missing_patch':'32876380', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.2.0.1.0',  'fixed_version': '12.2.0.1.210720', 'missing_patch':'32876409', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.2.0.1.0',  'fixed_version': '12.2.0.1.210720', 'missing_patch':'32905896', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.210720', 'missing_patch':'32876425', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.210720', 'missing_patch':'32905878', 'os':'win', 'component':'ojvm'}
];

vcf::oracle_rdbms::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

