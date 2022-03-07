#
# 
#

include("compat.inc");

if (description)
{
  script_id(137702);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/22");

  script_cve_id(
    "CVE-2020-11896",
    "CVE-2020-11897",
    "CVE-2020-11898",
    "CVE-2020-11899",
    "CVE-2020-11900",
    "CVE-2020-11901",
    "CVE-2020-11902",
    "CVE-2020-11903",
    "CVE-2020-11904",
    "CVE-2020-11905",
    "CVE-2020-11906",
    "CVE-2020-11907",
    "CVE-2020-11908",
    "CVE-2020-11909",
    "CVE-2020-11910",
    "CVE-2020-11911",
    "CVE-2020-11912",
    "CVE-2020-11913",
    "CVE-2020-11914"
  );

  script_name(english:"Treck TCP/IP stack multiple vulnerabilities. (Ripple20)");

  script_set_attribute(attribute:"synopsis", value:
"The Treck network stack used by the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"This plugin detects the usage of the Treck TCP/IP stack by the host thereby indicating that it could be potentially
vulnerable to the Ripple20 vulnerabilities. Patches are being slowly rolled out by vendors and we will release plugins
for patches as they are released by the vendors. In the interim, if you have applied the patches from the vendor for the
Ripple20 vulnerabilities on this host, please recast the severity of this plugin. Additional methods of detecting the
Treck stack will also be added soon to bolster coverage.");
  script_set_attribute(attribute:"see_also", value:"https://www.jsof-tech.com/ripple20/");
  # https://www.jsof-tech.com/wp-content/uploads/2020/06/JSOF_Ripple20_Technical_Whitepaper_June20.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?431098c1");
  script_set_attribute(attribute:"see_also", value:"https://support.hp.com/emea_africa-en/document/c06640149");
  script_set_attribute(attribute:"see_also", value:"https://psirt.bosch.com/security-advisories/BOSCH-SA-662084.html");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patches as they become available.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11896");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:treck:tcp_ip");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("treck_detect.nbin");
  script_require_keys("treck_network_stack");
  exit(0);
}

get_kb_item_or_exit("treck_network_stack");

report = '\n  Detected Treck TCP\\IP network stack.';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
