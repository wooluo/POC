#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126830);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/19 17:16:23");

  script_cve_id(
    "CVE-2016-9572",
    "CVE-2018-11058",
    "CVE-2019-2484",
    "CVE-2019-2569",
    "CVE-2019-2749",
    "CVE-2019-2753",
    "CVE-2019-2776",
    "CVE-2019-2799"
  );
  script_bugtraq_id(
    108106,
    109195,
    109203,
    109211,
    109214,
    109217,
    109224,
    109233
  );
  script_xref(name:"IAVA", value:"2019-A-0254");

  script_name(english:"Oracle Database Server Multiple Vulnerabilities (Jul 2019 CPU)");
  script_summary(english:"Checks installed patch info.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the July 2019 Critical Patch Update (CPU). It is, therefore, affected by
multiple vulnerabilities :

  - An unspecified vulnerability in the Spatial component of Oracle Database Server, which could allow an
    authenticated, remote attacker to cause a partial denial of service of Spatial. (CVE-2016-9572)

  - An unspecified vulnerability in the Core RDBMS component of Oracle Database Server, which could allow an
    unauthenticated, remote attacker to take over Core RDBMS (CVE-2018-11058)

  - An unspecified vulnerability in the Application Express component of Oracle Database Server, which could allow an
    authenticated, remote attacker to manipulate Application Express accessible data. (CVE-2019-2484)

  - An unspecified vulnerability in the Core RDBMS component of Oracle Database Server, which could allow an
    authenticated, local attacker complete access to all Core RDBMS accessible data. (CVE-2019-2569)

  - An unspecified vulnerability in the Java VM component of Oracle Database Server, which could allow an
    authenticated, remote attacker to manipulate Java VM accessible data or cause a complete denial of service of
    Java VM. (CVE-2019-2749)

  - An unspecified vulnerability in the Oracle Text component of Oracle Database Server, which could allow an
    authenticated, remote attacker to read a subset of Oracle Text accessible data or cause a partial denial of service
    of Oracle Text. (CVE-2019-2753)

  - An unspecified vulnerability in the Core RDBMS component of Oracle Database Server, which could allow an
    authenticated, remote attacker complete access to all Core RDBMS accessible data. (CVE-2019-2776)

  - An unspecified vulnerability in the Oracle ODBC Driver component of Oracle Database Server, which could allow an
    authenticated, remote attacker to take over Oracle ODBC Driver. Note this vulnerability only affects the Windows
    platform. (CVE-2019-2799)

Note that GizaNE has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html#AppendixDB
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2019 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11058");

  script_set_attribute(attribute:"vuln_publication_date",value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date",value:"2019/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/19");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

patches = make_nested_array();

# RDBMS 19.4.0.0
patches["19.4.0.0"]["db"]["nix"] = make_array("patch_level", "19.4.0.0.190716", "CPU", "29708769, 29834717");
patches["19.4.0.0"]["db"]["win"] = make_array("patch_level", "19.4.0.0.190716", "CPU", "29859191");
# RDBMS 18.7.0.0
patches["18.7.0.0"]["db"]["nix"] = make_array("patch_level", "18.7.0.0.190716", "CPU", "29708703, 29757256");
patches["18.7.0.0"]["db"]["win"] = make_array("patch_level", "18.7.0.0.190716", "CPU", "29859180");
# RDBMS 18.6.1.0
patches["18.6.1.0"]["db"]["nix"] = make_array("patch_level", "18.6.1.0.190716", "CPU", "29708235");
# RDBMS 18.5.2.0
patches["18.5.2.0"]["db"]["nix"] = make_array("patch_level", "18.5.2.0.190716", "CPU", "29708437");
# RDBMS 12.2.0.1
patches["12.2.0.1"]["db"]["nix"] = make_array("patch_level", "12.2.0.1.190716", "CPU", "29708381, 29708478, 29757449");
patches["12.2.0.1"]["db"]["win"] = make_array("patch_level", "12.2.0.1.190716", "CPU", "29832062");
# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.190716", "CPU", "29496791, 29494060");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.190716", "CPU", "29831650");
# RDBMS 11.2.0.4
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.190716", "CPU", "29698813, 29497421");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.190716", "CPU", "29596609");

# OJVM 19.4.0.0
patches["19.4.0.0"]["ojvm"]["nix"] = make_array("patch_level", "19.4.0.0.190716", "CPU", "29774421");
# OJVM 18.7.0.0
patches["18.7.0.0"]["ojvm"]["nix"] = make_array("patch_level", "18.7.0.0.190716", "CPU", "29774410");
patches["18.7.0.0"]["ojvm"]["win"] = make_array("patch_level", "18.7.0.0.190716", "CPU", "29774410");
# OJVM 12.2.0.1
patches["12.2.0.1"]["ojvm"]["nix"] = make_array("patch_level", "12.2.0.1.190716", "CPU", "29774415");
patches["12.2.0.1"]["ojvm"]["win"] = make_array("patch_level", "12.2.0.1.190716", "CPU", "29837425");
# OJVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.190716", "CPU", "29774383");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.190716", "CPU", "29837393");
# OVJM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.190716", "CPU", "29610422");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.190716", "CPU", "30012911");

check_oracle_database(patches:patches, high_risk:TRUE);
