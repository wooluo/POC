#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126781);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/23 10:11:24");

  script_cve_id("CVE-2019-0211", "CVE-2019-2751");
  script_bugtraq_id(107666, 109255);
  script_xref(name:"IAVA", value:"2019-A-0256");

  script_name(english:"Oracle Fusion Middleware Oracle HTTP Server (Jul 2019 CPU)");
  script_summary(english:"Checks the version of Oracle HTTP Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host is affected by the following vulnerabilities as noted in
the July 2019 CPU advisory : 

  - A privilege escalation vulnerability exists in the web listener component. An authenticated, local attacker can
    exploit this, to gain privileged access to the system. (CVE-2019-0211)

  - A security bypass vulnerability exists in the OHS Config MBeans component. An unauthenticated, remote attacker can
    exploit this, to access confidential information. (CVE-2019-2751)");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2019 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0211");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

get_kb_item_or_exit('Oracle/OHS/Installed');
installs = get_kb_list_or_exit('Oracle/OHS/*/Version');

patches = make_array();
patches['12.2.1.3'] = make_list('29794278');

oracle_product_check_vuln(
  product  : 'Oracle HTTP Server',
  installs : installs,
  kbprefix : 'Oracle/OHS/',
  patches  : patches
);
