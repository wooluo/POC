#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121421);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/17  5:21:49");

  script_cve_id("CVE-2019-2414");

  script_bugtraq_id(106621);

  script_name(english:"Oracle Fusion Middleware Oracle HTTP Server Multiple Vulnerabilities (January 2019 CPU)");
  script_summary(english:"Checks the version of Oracle HTTP Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host is
affected by vulnerabilities as noted in the January 2019 CPU advisory:

  - This vulnerability is in the Oracle HTTP server component of Oracle
    Fusion Middleware (subcomponent: Web Listener). The affected version
    is 12.1.2.3. This is an easily exploitable vulnerability that allows
    a low privileged attacker with logon to the infrastructure where
    Oracle HTTP Server executes to compromise the Oracle HTTP Server.
    Successful attacks of this vulnerability can result in takeover on
    Oracle HTTP Server. (CVE-2019-2414)");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate
patch according to the January 2019 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2414");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
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
patches['12.2.1.3'] = make_list('29058843', '28281599', '29407043');

# security warning
oracle_product_check_vuln(
  product  : 'Oracle HTTP Server',
  installs : installs,
  kbprefix : 'Oracle/OHS/',
  patches  : patches
);
