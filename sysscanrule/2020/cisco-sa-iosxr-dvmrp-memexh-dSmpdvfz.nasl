#TRUSTED 809740cfeaa12f2d6f9d3a13000c461f058064f0ef56e657d4493cf33ba767ba7cdc6c4788334ab6b374186da93a5c675dc9f1d8df6c1b26778a83ba81d468a59a1c709ee41a5d5ac5de53da8addcd81e5135327bfcd5ee130ac5b2f9c0b404f9fe5ceb8db3cba04668390160f4bb9936bd965e5c2b2bee8e97e7840fb441e5eedebc81b3044b33e9f41e94e86f5eebd6ab74fb1b4a6afcbc49deb7ee4299680fcb7ba48361603ac5c25fe5ad683f1271988da8281a1e4e50ef25a2dc222c400d6f3474f5cfbee85aacee4a1cf1eaefc50739bc7563e20fa8027192441627f5da63e25730e48ba73116a6fc194ffbf4294dc3d665fb4ccdfed87e68be60f7c5da0899dab5becd30524754d329fc1deca5c3a9ca2e5c5a048afc2892c441e2e2dea7b1f63556867636c50b6cda74610591c54db2d808d4e057e90666dedef7b9a3c5066db1f9cdb549167bbcbcdaf13779009e8710c9ddefc6a3c0660d59e23b1e5de1fd9cc20af7e96bc328168916123423607f3ae2f22473bd0c06ee0dc26590c89e69d17aef4b4b6c9663a9e3ffd33a540c68014ac270c0627313f28e56165865150470fbeaff2f6e26fa5f5c6c10edea2a52b0587a3742bdd5e6121e0b5a42847503e6478fbbafcaa1575eed3d966bfab70f7bf83af4f4012e266c3d8d45f6319b52fdfd6c7452ad8f98215d9f4689d3e38e20d345078af448f1da9e3b3cb
#
# 
#

include('compat.inc');

if (description)
{
  script_id(140111);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/01");

  script_cve_id("CVE-2020-3566", "CVE-2020-3569");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr86414");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv54838");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-dvmrp-memexh-dSmpdvfz");

  script_name(english:"Cisco IOS XR Software DVMRP Memory Exhaustion Vulnerabilities (cisco-sa-iosxr-dvmrp-memexh-dSmpdvfz)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported configuration, Cisco IOS XR Software is affected by multiple vulnerabilities:

  - Multiple denial of service (DoS) vulnerabilities exist in the Distance Vector Multicast Routing Protocol (DVMRP)
    feature due to insufficient queue management for Internet Group Management Protocol (IGMP) packets. An 
    unauthenticated, remote attacker could exploit this issue by sending crafted IGMP traffic to an affected
    device, to cause memory exhaustion resulting in instability of other processes. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number and configuration.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-dvmrp-memexh-dSmpdvfz
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?44ee1673");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr86414");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv54838");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr86414, CSCvv54838");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3566");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

workarounds = make_list(CISCO_WORKAROUNDS['disable_igmp_multicast_routing']);

vuln_ranges = [ {'min_ver':'0.0', 'fix_ver':'9999'} ];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr86414, CSCvv54838',
  'fix'      , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  vuln_ranges:vuln_ranges
);
