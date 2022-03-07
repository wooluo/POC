#
# 
#

include('compat.inc');

if (description)
{
  script_id(141829);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/26");

  script_cve_id(
    "CVE-2019-12900",
    "CVE-2020-9281",
    "CVE-2020-11023",
    "CVE-2020-13935",
    "CVE-2020-14734",
    "CVE-2020-14735",
    "CVE-2020-14736",
    "CVE-2020-14740",
    "CVE-2020-14741",
    "CVE-2020-14742",
    "CVE-2020-14743",
    "CVE-2020-14762",
    "CVE-2020-14763",
    "CVE-2020-14898",
    "CVE-2020-14899",
    "CVE-2020-14900",
    "CVE-2020-14901"
  );
  script_xref(name:"IAVA", value:"2020-A-0475");

  script_name(english:"Oracle Database Server Multiple Vulnerabilities (Oct 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Database Server installed on the remote host are affected by multiple vulnerabilities as
referenced in the October 2020 CPU advisory.

  - Vulnerability in the Core RDBMS (bzip2) component of Oracle Database Server. Supported versions that are 
  affected are 11.2.0.4, 12.1.0.2, 12.2.0.1, 18c and 19c. Easily exploitable vulnerability allows low 
  privileged attacker having DBA Level Account privilege with network access via Oracle Net to compromise 
  Core RDBMS (bzip2). Successful attacks of this vulnerability can result in takeover of Core RDBMS (bzip2).
  (CVE-2019-12900)
  
  - Vulnerability in the Core RDBMS (bzip2) component of Oracle Database Server. Supported versions that 
  are affected are 11.2.0.4, 12.1.0.2, 12.2.0.1, 18c and 19c. Easily exploitable vulnerability allows low 
  privileged attacker having DBA Level Account privilege with network access via Oracle Net to compromise 
  Core RDBMS (bzip2). Successful attacks of this vulnerability can result in takeover of Core RDBMS (bzip2).
  (CVE-2020-14735)

  - Vulnerability in the Oracle Text component of Oracle Database Server. Supported versions that are affected
  are 11.2.0.4, 12.1.0.2, 12.2.0.1, 18c and 19c. Difficult to exploit vulnerability allows unauthenticated 
  attacker with network access via Oracle Net to compromise Oracle Text. Successful attacks of this 
  vulnerability can result in takeover of Oracle Text. (CVE-2020-14734)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12900");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
patches['19.9']['db']['nix'] = make_array('patch_level', '19.9.0.0.201020', 'CPU', '31771877');
patches['19.9']['db']['win'] = make_array('patch_level', '19.9.0.0.201020', 'CPU', '31719903');
patches['19.8']['db']['nix'] = make_array('patch_level', '19.8.1.0.201020', 'CPU', '31666885');
patches['19.7']['db']['nix'] = make_array('patch_level', '19.7.2.0.201020', 'CPU', '31667176');

patches['18.12.0.0']['db']['nix'] = make_array('patch_level', '18.12.0.0.201020', 'CPU', '31730250');
patches['18.12.0.0']['db']['win'] = make_array('patch_level', '18.12.0.0.201020', 'CPU', '31629682');
patches['18.11.1.0']['db']['nix'] = make_array('patch_level', '18.11.1.0.201020', 'CPU', '31666917');
patches['18.10.2.0']['db']['nix'] = make_array('patch_level', '18.10.2.0.201020', 'CPU', '31667173');

patches['12.2.0.1']['db']['nix'] = make_array('patch_level', '12.2.0.1.201020', 'CPU', '31741641, 31667168, 31666944');
patches['12.2.0.1']['db']['win'] = make_array('patch_level', '12.2.0.1.201020', 'CPU', '31654782');

# 31511219 in Proactive BP below
patches['12.1.0.2']['db']['nix'] = make_array('patch_level', '12.1.0.2.201020', 'CPU', '31550110, 31511219');
patches['12.1.0.2']['db']['win'] = make_array('patch_level', '12.1.0.2.201020', 'CPU', '31658987');

# 31537652 in Exadata BP
patches['11.2.0.4']['db']['nix'] = make_array('patch_level', '11.2.0.4.201020', 'CPU', '31537677, 31834759, 31537652'); 
# Note: Patch level below is 200414 on main DB page, but inside patch is 201020.
patches['11.2.0.4']['db']['win'] = make_array('patch_level', '11.2.0.4.201020', 'CPU', '31659823');

# OJVM 
patches['19.9']['ojvm']['nix'] = make_array('patch_level', '19.9.0.0.201020', 'CPU', '31668882');
patches['19.9']['ojvm']['win'] = make_array('patch_level', '19.9.0.0.201020', 'CPU', '31668882');

patches['18.12.0.0']['ojvm']['nix'] = make_array('patch_level', '18.12.0.0.201020', 'CPU', '31668892');
patches['18.12.0.0']['ojvm']['win'] = make_array('patch_level', '18.12.0.0.201020', 'CPU', '31668892');

patches['12.2.0.1']['ojvm']['nix'] = make_array('patch_level', '12.2.0.1.201020', 'CPU', '31668898');
patches['12.2.0.1']['ojvm']['win'] = make_array('patch_level', '12.2.0.1.201020', 'CPU', '31740064');

patches['12.1.0.2']['ojvm']['nix'] = make_array('patch_level', '12.1.0.2.201020', 'CPU', '31668915');
patches['12.1.0.2']['ojvm']['win'] = make_array('patch_level', '12.1.0.2.201020', 'CPU', '31740134');

patches['11.2.0.4']['ojvm']['nix'] = make_array('patch_level', '11.2.0.4.201020', 'CPU', '31668908');
# Note: Patch level below is 200414 on main DB page, but inside patch is 201020.
patches['11.2.0.4']['ojvm']['win'] = make_array('patch_level', '11.2.0.4.201020', 'CPU', '31740195');

check_oracle_database(patches:patches, high_risk:TRUE);
