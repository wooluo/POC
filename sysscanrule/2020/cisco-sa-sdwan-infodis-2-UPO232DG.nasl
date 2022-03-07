#TRUSTED 67e6a249e8ac21f6561bc7a0113d51050d2e9e26ed891c8a2820bdd142de18f6ae0c66d9dd98b20ffdf04890288a6c3cd21385661d3b53d6219bbcafcc21bb9ceb75cce33e9b4a2c9987a88eae723c42cf82a55e99ce9e0b25986da477adf637b672cf8cfb7b384b2310b80903c7038a4bde13319ba58ccfe79888eca34dfc2185b5b3c3f68f0ccf1390955a572525e98d1bcefc01e115fc51b9e7826cc42e76597502ea02e19cbbb38834473d98de33795648a08b542101fbf806e10fd3cdf2f32315042b02c562806049be50e2c4355a782decb57e94b300e1e5c2d178e786f667e6ab507b89edbcb66bf251b9c692684b59ad76c5faadbbf6ef57f59375272473bea164ae0aa9b036e3550c4a515da1cd475690e2adcddc5d52341918735dcf32935f3c50560d978884b09f67b045721a9e5c5965e8bd2a1c5af990c387e51913f7fd114d2a94c350b9c52fc9b733465cf862d2e584134f795cb89c24eb59653bd324f80233a9802d887183fb76913650b8a1fcdd610c600a2195bb83662e8f1b3599492853ec28d4c34149aa3c0fcf693a648bf675e61f5f018cf7e10af6e3a2ddb7f033a3f6c9eb7c3555897188cef4f36ece56d7ab194e448ca53143f2026faee3d6407e0a6d541da547a5c1b70e3bc5beb07a21cbdff23d02fef04ad33a3ca99697b2a55493f9648825f058e6f2d3537c6f166e64cf9e5094d5d8fa98
##
# 
##

include('compat.inc');

if (description)
{
  script_id(146307);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/11");

  script_cve_id("CVE-2021-1233");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi69962");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-infodis-2-UPO232DG");
  script_xref(name:"IAVA", value:"2021-A-0045");

  script_name(english:"Cisco SD-WAN Information Disclosure (cisco-sa-sdwan-infodis-2-UPO232DG)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, an information disclosure vulnerability exists in the CLI of Cisco SD-WAN
Software due to insufficient input validation of requests that are sent to the iperf tool. An unauthenticated, local
attacker can exploit this, by sending a crafted request to the iperf tool, which is included in Cisco SD-WAN Software,
to disclose potentially sensitive information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-infodis-2-UPO232DG
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28a8cdc0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi69962");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi69962");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1233");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model'] !~ "vmanage|vbond|vedge"))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'18.4.3'},
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi69962',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
