#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124155);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/18 15:47:53");

  script_cve_id(
    "CVE-2019-2516",
    "CVE-2019-2517",
    "CVE-2019-2518",
    "CVE-2019-2571",
    "CVE-2019-2582",
    "CVE-2019-2619"
  );
  script_bugtraq_id(
    107919,
    107936,
    107940,
    107945
  );

  script_name(english:"Oracle Database Server Multiple Vulnerabilities (Apr 2019 CPU)");
  script_summary(english:"Checks installed patch info.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the April 2019
Critical Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities :

  - An authenticated local Portable Clusterware takeover
    vulnerability exists in the Oracle RDBMS. An authenticated, local
    attacker with the Grid Infrastructure User privilege with logon
    to the infrastructure where Portable Clusterware executes can
    exploit this to take over the Portable Clusterware component of
    Oracle RDBMS, resulting in the disclosure or manipulation of
    arbitrary data. (CVE-2019-2516) (CVE-2019-2619)

  - An authenticated remote database takeover vulnerability exists in
    the Oracle RDBMS. An authenticated, remote attacker with the
    DBFS_ROLE privilege can exploit this via the Oracle Net protocol
    to take over the back-end database, resulting in the disclosure
    or manipulation of arbitrary data. (CVE-2019-2517)

  - An authenticated remote Java VM takeover vulnerability exists in
    the Oracle RDBMS. An authenticated, remote attacker with the
    Create Session, Create Procedure privileges can exploit this to
    take over the Java VM. (CVE-2019-2518)

  - An authenticated remote RDBMS DataPump takeover vulnerability
    exists in the Oracle RDBMS. An authenticated, remote attacker
    with the DBA role privilege can exploit this via the Oracle Net
    protocol to take over the RDBMS DataPump component of Oracle
    RDBMS. (CVE-2019-2571)

  - An unauthenticated remote information disclosure vulnerability
    exists in the Oracle RDBMS. An unauthenticated, remote attacker
    can exploit this via the Oracle Net protocol to obtain read
    access to a unspecified subset of Core RDBMS accessible data.
    (CVE-2019-2582)

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html#AppendixDB
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2019 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2517");

  script_set_attribute(attribute:"vuln_publication_date",value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date",value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/18");

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

patches = make_nested_array();

# RDBMS 18.6.0.0
patches["18.6.0.0"]["db"]["nix"] = make_array("patch_level", "18.6.0.0.190416", "CPU", "29301631");
patches["18.6.0.0"]["db"]["win"] = make_array("patch_level", "18.6.0.0.190416", "CPU", "29589622");
# RDBMS 18.5.1.0
patches["18.5.1.0"]["db"]["nix"] = make_array("patch_level", "18.5.1.0.190416", "CPU", "29230887");
# RDBMS 18.4.2.0
patches["18.4.2.0"]["db"]["nix"] = make_array("patch_level", "18.4.2.0.190416", "CPU", "29230809");
# RDBMS 12.2.0.1
patches["12.2.0.1"]["db"]["nix"] = make_array("patch_level", "12.2.0.1.190416", "CPU", "29314339, 29230821, 29230950");
patches["12.2.0.1"]["db"]["win"] = make_array("patch_level", "12.2.0.1.190416", "CPU", "29394003");
# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.190416", "CPU", "29141015, 29141038");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.190416", "CPU", "29413116");
# RDBMS 11.2.0.4
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.190416", "CPU", "29141056, 29257245");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.190416", "CPU", "29218820");

# OJVM 19.3.0.0
patches["19.3.0.0"]["ojvm"]["nix"] = make_array("patch_level", "19.3.0.0.190416", "CPU", "29548437");
# OJVM 18.6.0.0
patches["18.6.0.0"]["ojvm"]["nix"] = make_array("patch_level", "18.6.0.0.190416", "CPU", "29249584");
patches["18.6.0.0"]["ojvm"]["win"] = make_array("patch_level", "18.6.0.0.190416", "CPU", "29249584");
# OJVM 12.2.0.1
patches["12.2.0.1"]["ojvm"]["nix"] = make_array("patch_level", "12.2.0.1.190416", "CPU", "29249637");
patches["12.2.0.1"]["ojvm"]["win"] = make_array("patch_level", "12.2.0.1.190416", "CPU", "29281550");
# OJVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.190416", "CPU", "29251241");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.190416", "CPU", "29447962");
# OVJM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.190416", "CPU", "29251270");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.190416", "CPU", "29447971");

check_oracle_database(patches:patches, high_risk:TRUE);
