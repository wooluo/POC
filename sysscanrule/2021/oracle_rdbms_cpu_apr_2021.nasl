##
# 
##

include('compat.inc');

if (description)
{
  script_id(148894);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/22");

  script_cve_id(
    "CVE-2019-3738",
    "CVE-2019-3739",
    "CVE-2019-3740",
    "CVE-2019-11358",
    "CVE-2020-5359",
    "CVE-2020-5360",
    "CVE-2020-7760",
    "CVE-2020-9484",
    "CVE-2020-11022",
    "CVE-2020-11023",
    "CVE-2020-13943",
    "CVE-2020-17527",
    "CVE-2021-2173",
    "CVE-2021-2175",
    "CVE-2021-2207",
    "CVE-2021-2234",
    "CVE-2021-2245"
  );

  script_name(english:"Oracle Database Server Multiple Vulnerabilities (Apr 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a database server which is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Database Server installed on the remote host are affected by multiple vulnerabilities as
referenced in the April 2021 CPU advisory. 

  - Vulnerability in the Oracle Database - Enterprise Edition Security (Dell BSAFE Micro Edition Suite) 
  component of Oracle Database Server. Supported versions that are affected are 12.1.0.2, 12.2.0.1, 18c
  and 19c. Easily exploitable vulnerability allows unauthenticated attacker with network access via 
  multiple protocols to compromise Oracle Database - Enterprise Edition Security (Dell BSAFE Micro Edition Suite). 
  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently 
  repeatable crash (complete DOS) of Oracle Database - Enterprise Edition Security (Dell BSAFE Micro Edition Suite) 
  (CVE-2020-5360).

  - Vulnerability in the Workload Manager (Apache Tomcat) component of Oracle Database Server. Supported versions 
  that are affected are 18c and 19c. Easily exploitable vulnerability allows unauthenticated attacker with network 
  access via HTTP to compromise Workload Manager (Apache Tomcat). Successful attacks of this vulnerability can 
  result in unauthorized access to critical data or complete access to all Workload Manager (Apache Tomcat) 
  accessible data (CVE-2020-17527).

  - Vulnerability in the Oracle Database - Enterprise Edition (Dell BSAFE Crypto-J) component of Oracle Database 
  Server. Supported versions that are affected are 12.1.0.2, 12.2.0.1, 18c and 19c. Easily exploitable vulnerability
  allows unauthenticated attacker with network access via Oracle Net to compromise Oracle Database - Enterprise 
  Edition (Dell BSAFE Crypto-J). Successful attacks require human interaction from a person other than the attacker. 
  Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to 
  all Oracle Database - Enterprise Edition (Dell BSAFE Crypto-J) accessible data (CVE-2019-3740). 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5359");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include('vcf_extras_oracle.inc');

app_info = vcf::oracle_rdbms::get_app_info();

constraints = [
  # RDBMS:
  {'min_version': '19.0', 'fixed_version': '19.9.2.0.210420', 'missing_patch':'32421507', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.11.0.0.210420', 'missing_patch':'32409154', 'os':'win', 'component':'db'},
  {'min_version': '19.10', 'fixed_version': '19.10.1.0.210420', 'missing_patch':'32441092', 'os':'unix', 'component':'db'},
  {'min_version': '19.11', 'fixed_version': '19.11.0.0.210420', 'missing_patch':'32545013', 'os':'unix', 'component':'db'},
  
  {'min_version': '18.0',  'fixed_version': '18.12.2.0.210420', 'missing_patch':'32421478', 'os':'unix', 'component':'db'},
  {'min_version': '18.0',  'fixed_version': '18.14.0.0.210420', 'missing_patch':'32438481', 'os':'win', 'component':'db'},
  {'min_version': '18.13', 'fixed_version': '18.13.1.0.210420', 'missing_patch':'32451079', 'os':'unix', 'component':'db'},
  {'min_version': '18.14', 'fixed_version': '18.14.0.0.210420', 'missing_patch':'32524155', 'os':'unix', 'component':'db'},
 
  {'min_version': '12.2.0.1.0', 'fixed_version': '12.2.0.1.210420', 'missing_patch':'32507738', 'os':'unix', 'component':'db'},
  {'min_version': '12.2.0.1.0', 'fixed_version': '12.2.0.1.210420', 'missing_patch':'32392089', 'os':'win', 'component':'db'},

  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.210420', 'missing_patch':'32328635, 32328632', 'os':'unix', 'component':'db'},
  {'min_version': '12.1.0.2.0', 'fixed_version': '12.1.0.2.210420', 'missing_patch':'32396181', 'os':'win', 'component':'db'},
  
  # OJVM:
  {'min_version': '19.0',  'fixed_version': '19.11.0.0.210420', 'missing_patch':'32399816', 'os':'unix', 'component':'ojvm'},
  {'min_version': '19.0',  'fixed_version': '19.11.0.0.210420', 'missing_patch':'32399816', 'os':'win', 'component':'ojvm'},

  {'min_version': '18.0',  'fixed_version': '18.14.0.0.210420', 'missing_patch':'32552752', 'os':'unix', 'component':'ojvm'},
  {'min_version': '18.0',  'fixed_version': '18.14.0.0.210420', 'missing_patch':'32552752', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.2.0.1.0',  'fixed_version': '12.2.0.1.210420', 'missing_patch':'32473172', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.2.0.1.0',  'fixed_version': '12.2.0.1.210420', 'missing_patch':'32427674', 'os':'win', 'component':'ojvm'},

  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.210420', 'missing_patch':'32473164', 'os':'unix', 'component':'ojvm'},
  {'min_version': '12.1.0.2.0',  'fixed_version': '12.1.0.2.210420', 'missing_patch':'32427683', 'os':'win', 'component':'ojvm'}
 
];

vcf::oracle_rdbms::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

