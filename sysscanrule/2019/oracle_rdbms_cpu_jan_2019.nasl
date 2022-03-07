#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121253);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/18 12:05:36");

  script_cve_id(
    "CVE-2019-2406",
    "CVE-2019-2444",
    "CVE-2019-2547"
  );
  script_bugtraq_id(
    106584,
    106591,
    106594
  );

  script_name(english:"Oracle Database Server Multiple Vulnerabilities (Jan 2019 CPU)");
  script_summary(english:"Checks installed patch info.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the January 2019
Critical Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities :

  - An authenticated remote database takeover vulnerability exists in
    the Oracle RDBMS. An authenticated, remote attacker with the
    Create Session, Execute Catalog Role privileges can exploit this
    via the Oracle Net protocol to take over the back-end database,
    resulting in the disclosure or manipulation of arbitrary data.
    (CVE-2019-2406)

  - An authenticated local database takeover vulnerability exists in
    the Oracle RDBMS. An authenticated, local attacker with the Local
    Logon privilege can exploit this, by convincing another user to
    perform an unspecified action, to take over the back-end
    database, resulting in the disclosure or manipulation of
    arbitrary data. (CVE-2019-2444)

  - A denial of service (DoS) vulnerability exists in the Oracle
    RDBMS. An authenticated, remote attacker with the Create Session,
    Create Procedure privileges can exploit this issue, via
    multiple network protocols, by convincing another use to perform
    an unspecified action, to cause the Java VM to stop responding.
    (CVE-2019-2547)

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html#AppendixDB
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2019 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2444");

  script_set_attribute(attribute:"vuln_publication_date",value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date",value:"2019/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/18");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:database_server");
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

ipatches = make_nested_array();
# 18.5.0.0
patches["18.5.0.0"]["db"]["nix"] = make_array("patch_level", "18.5.0.0.190115", "CPU", "28822489");
patches["18.5.0.0"]["db"]["win"] = make_array("patch_level", "18.5.0.0.190115", "CPU", "29124511");
# 18.4.1.0
patches["18.4.1.0"]["db"]["nix"] = make_array("patch_level", "18.4.1.0.190115", "CPU", "28822587");
# 18.3.2.0
patches["18.3.2.0"]["db"]["nix"] = make_array("patch_level", "18.3.2.0.190115", "CPU", "28790643");

# RDBMS 12.2.0.1
patches["12.2.0.1"]["db"]["nix"] = make_array("patch_level", "12.2.0.1.190115", "CPU", "28822515, 28790640, 28822638");
patches["12.2.0.1"]["db"]["win"] = make_array("patch_level", "12.2.0.1.190115", "CPU", "28810696");
# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.190115", "CPU", "28729169, 28731800");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.190115", "CPU", "28810679");
# RDBMS 11.2.0.4
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.190115", "CPU", "28729262, 28790634");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.190115", "CPU", "28761877");

# OJVM 18.5.0.0
patches["18.5.0.0"]["ojvm"]["nix"] = make_array("patch_level", "18.5.0.0.190115", "CPU", "28790647");
# OJVM 12.2.0.1
patches["12.2.0.1"]["ojvm"]["nix"] = make_array("patch_level", "12.2.0.1.190115", "CPU", "28790651");
patches["12.2.0.1"]["ojvm"]["win"] = make_array("patch_level", "12.2.0.1.190115", "CPU", "28994068");
# OJVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.190115", "CPU", "28790654");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.190115", "CPU", "28994063");
# OJVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.190115", "CPU", "28790660");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.190115", "CPU", "28994059");

check_oracle_database(patches:patches);
