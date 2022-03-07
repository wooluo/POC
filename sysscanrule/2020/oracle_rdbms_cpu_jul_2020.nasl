#
# 
#

include('compat.inc');

if (description)
{
  script_id(138528);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/24");

  script_cve_id(
    "CVE-2016-9843",
    "CVE-2016-1000031",
    "CVE-2018-18314",
    "CVE-2019-10086",
    "CVE-2019-13990",
    "CVE-2019-16943",
    "CVE-2019-17569",
    "CVE-2020-2513",
    "CVE-2020-2968",
    "CVE-2020-2969",
    "CVE-2020-2971",
    "CVE-2020-2972",
    "CVE-2020-2973",
    "CVE-2020-2974",
    "CVE-2020-2975",
    "CVE-2020-2976",
    "CVE-2020-2977",
    "CVE-2020-2978",
    "CVE-2020-8112"
  );
  script_bugtraq_id(93604, 95131, 106145);
  script_xref(name:"IAVA", value:"2020-A-0328");

  script_name(english:"Oracle Database Server Multiple Vulnerabilities (Jul 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Database Server installed on the remote host are affected by multiple vulnerabilities as
referenced in the July 2020 CPU advisory.

  - Vulnerability in the MapViewer (Apache Commons
    FileUpload) component of Oracle Database Server.
    Supported versions that are affected are 12.2.0.1, 18c
    and 19c. Easily exploitable vulnerability allows low
    privileged attacker having Valid User Account privilege
    with network access via HTTP to compromise MapViewer
    (Apache Commons FileUpload). Successful attacks of this
    vulnerability can result in takeover of MapViewer
    (Apache Commons FileUpload). Note: MapViewer is not
    deployed with a default installation. To use MapViewer
    the customer needs to re-deploy MapViewer EAR file into
    Oracle WebLogic Server. CVSS 3.1 Base Score 8.8
    (Confidentiality, Integrity and Availability impacts).
    (CVE-2016-1000031)

  - Vulnerability in the Java VM component of Oracle
    Database Server. Supported versions that are affected
    are 11.2.0.4, 12.1.0.2, 12.2.0.1, 18c and 19c. Difficult
    to exploit vulnerability allows low privileged attacker
    having Create Session, Create Procedure privilege with
    network access via multiple protocols to compromise Java
    VM. Successful attacks require human interaction from a
    person other than the attacker and while the
    vulnerability is in Java VM, attacks may significantly
    impact additional products. Successful attacks of this
    vulnerability can result in takeover of Java VM. CVSS
    3.1 Base Score 8.0 (Confidentiality, Integrity and
    Availability impacts). (CVE-2020-2968)

  - Vulnerability in the Core RDBMS (zlib) component of
    Oracle Database Server. The supported version that is
    affected is 18c. Easily exploitable vulnerability allows
    high privileged attacker having Create Session privilege
    with network access via Oracle Net to compromise Core
    RDBMS (zlib). Successful attacks of this vulnerability
    can result in takeover of Core RDBMS (zlib). CVSS 3.1
    Base Score 7.2 (Confidentiality, Integrity and
    Availability impacts).(CVE-2016-9843)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2020 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1000031");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include('oracle_rdbms_cpu_func.inc');

patches = make_nested_array();

# RDBMS
patches['19.8.0.0']['db']['nix'] = make_array('patch_level', '19.8.0.0.200714', 'CPU', '31281355');
patches['19.8.0.0']['db']['win'] = make_array('patch_level', '19.8.0.0.200714', 'CPU', '31247621');
patches['19.7.1.0']['db']['nix'] = make_array('patch_level', '19.7.1.0.200714', 'CPU', '31204483');
patches['19.6.2.0']['db']['nix'] = make_array('patch_level', '19.6.2.0.200714', 'CPU', '31212138');

patches['18.11.0.0']['db']['nix'] = make_array('patch_level', '18.11.0.0.200714', 'CPU', '31308624');
patches['18.11.0.0']['db']['win'] = make_array('patch_level', '18.11.0.0.200714', 'CPU', '31247612');
patches['18.10.1.0']['db']['nix'] = make_array('patch_level', '18.10.1.0.200714', 'CPU', '31211410');
patches['18.9.2.0']['db']['nix'] = make_array('patch_level', '18.9.2.0.200714', 'CPU', '31212186');

patches['12.2.0.1']['db']['nix'] = make_array('patch_level', '12.2.0.1.200714', 'CPU', '31312468, 31212219, 31199988');
patches['12.2.0.1']['db']['win'] = make_array('patch_level', '12.2.0.1.200714', 'CPU', '31210848');

patches['12.1.0.2']['db']['nix'] = make_array('patch_level', '12.1.0.2.200714', 'CPU', '31113348, 31001106');
patches['12.1.0.2']['db']['win'] = make_array('patch_level', '12.1.0.2.200714', 'CPU', '31211574');

patches['11.2.0.4']['db']['nix'] = make_array('patch_level', '11.2.0.4.200714', 'CPU', '31103343, 31338362, 31103314');
patches['11.2.0.4']['db']['win'] = make_array('patch_level', '11.2.0.4.200714', 'CPU', '31169916');

# OJVM 
patches['19.8.0.0']['ojvm']['nix'] = make_array('patch_level', '19.8.0.0.200714', 'CPU', '31219897');
patches['19.8.0.0']['ojvm']['win'] = make_array('patch_level', '19.8.0.0.200714', 'CPU', '31219897');

patches['18.11.0.0']['ojvm']['nix'] = make_array('patch_level', '18.11.0.0.200714', 'CPU', '31219909');
patches['18.11.0.0']['ojvm']['win'] = make_array('patch_level', '18.11.0.0.200714', 'CPU', '31219909');

patches['12.2.0.1']['ojvm']['nix'] = make_array('patch_level', '12.2.0.1.200714', 'CPU', '31219919');
patches['12.2.0.1']['ojvm']['win'] = make_array('patch_level', '12.2.0.1.200714', 'CPU', '31465105');

patches['12.1.0.2']['ojvm']['nix'] = make_array('patch_level', '12.1.0.2.200714', 'CPU', '31219939');
patches['12.1.0.2']['ojvm']['win'] = make_array('patch_level', '12.1.0.2.200714', 'CPU', '31465095');

patches['11.2.0.4']['ojvm']['nix'] = make_array('patch_level', '11.2.0.4.200714', 'CPU', '31219953');
patches['11.2.0.4']['ojvm']['win'] = make_array('patch_level', '11.2.0.4.200414', 'CPU', '31169933');

check_oracle_database(patches:patches, high_risk:TRUE);
