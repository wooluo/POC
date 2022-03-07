#TRUSTED 6605a944b137042ac23d9157772955f34798795adc8993724846c41b4e50a860416e3b2df72fa50a514327c916683d828607b17e191b4dce1b7205b23996f4800c8f627f241ec2e31f35ad6ab1a19a4faf204971d4ad0a34ab220668da1aa4ee7f8ed69a849f6c6b9a185284474d6be4600656283d6170e2dd9eaef76d136115c379dc1969f041cffa4b22fa4f0268f03380a6f38a7b0d1c80691dd58ca29feecb0de66a1364694f4ed30fc1082e1607ec5c63788ae31922dec61fdce51007d087ec56aa415a0697f840fca2cf94e4f36ce64ed7ca7150c2f754cc19f956d8eaf2b1381f2e3dc62f14575625cb980b566691c09bd9143e7965d41e1ffd311e609024f3b147673e1829e6590882b97ef16fe49b289694ba8aa4d3215d84300607f31382127b298e5e6963a1bd7256b328c96c12f7da7ceda346a1536b8fab9b5ab4259b563fc79564bca466469adcf393a69e185b72a8eb8d7aa914eb3e3fa7e2a9d6962b1882b4755847e93c6a7f2369e906d4ae030ecb83c538e00cf365df54121c7f49b41ecadbb6e832f98762896a78815c9b41e0d34b66c430c935512903ef60c1b3a916479efeb37862a38c73db5b48121580500843d27628165855facadc52c3d04559905f143dc572871c174695b97e74b2736845ead76dfc1e760871c248e7315ea8cd4d7d470d5288cdc3b017dc6bf1e71cefcdce0db4d3ffcc5cb5

##
# 
##



include('compat.inc');

if (description)
{
  script_id(150073);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/01");

  script_cve_id("CVE-2021-1378");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu59686");
  script_xref(name:"CISCO-SA", value:"cisco-sa-StarOS-DoS-RLLvGFJj");

  script_name(english:"Cisco StarOS DoS (cisco-sa-StarOS-DoS-RLLvGFJj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the SSH service of the Cisco StarOS operating system is affected by denial of 
service vulnerability due to a logic error that may occur under specific traffic conditions. An unauthenticated, remote 
attacker could exploit this by sending a series of crafted packets to an affected device. A successful exploit could 
allow the attacker to prevent the targeted service from receiving any traffic, which would lead to a DoS condition on 
the affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-StarOS-DoS-RLLvGFJj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?446bb3a4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu59686");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu59686");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1378");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:staros");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/StarOS/Version");

  exit(0);
}

include('ccf.inc');

var product_info,vuln_ranges, reporting;

product_info = cisco::get_product_info(name:'StarOS');

vuln_ranges = [
  {'min_ver' : '21.9.0', 'fix_ver' : '21.20.0'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu59686',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
