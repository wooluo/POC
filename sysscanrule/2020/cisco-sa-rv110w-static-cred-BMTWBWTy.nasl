#TRUSTED 1dbaebde015527a20233897cf5d874997964187d16298711c90cf8e594a7a55007278d0ed28e0def0da57af857f946cf2d6187cce94443f89a88a2f1e4d21d1b070858e20cb6ebbd1fbeb312ce4b0c4c99f7c50af70ba88c107d874a534f4a87b646ff6d7665ac05bc7c7ea9c04cb4ef5bfb939dd36dba7d49511f47ef36a8c88f6a320ab40593a6a4ab39e096940c83c6874b5a115b1d6ba5a4db2f9b37655539cf6a402cf08ce645f8a0394ec5a67dc0b24ec36f3f36e9ffcf2c310494a09ee989551af01b5d3eeea1945add15d0aa859a93e331be64392b9c46414f87336e523d3973db3c0db77438b27bdbccb7ca4c6739dba64bb034a2e8fd9cb821a20966c71210956057325b553fece7beeb2db31f249f7b049496d98f4425f7b02dead11df25b70d2935ee03b5f4de5cd34cf366780ce33d91f775124214e053e34da689504257a079193020679d0d61796d98590cfa760ead50616c30ae11b60fda16e5b528f56d77dc0b9ae7d21c8e499de432e6979fd8f33c58ab95488daaf774ba1b0a7489e79c26b12154004ab8094f9b823c3e1ec2e4c1175586835b5c1edf82cd8e772503ef1f35354dd09d9391340c4c478c56a62c599fe0112bb0f65c3ceeb522698c14f82d17995e129a4ef724b065487f54b1cd4a6159642b3c9130db2afd5be647a4771b4f4afce291c3e6eba58ede986b7a45c83cbdf4ad92a1bc298
#
# 
#

include('compat.inc');

if (description)
{
  script_id(139747);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/24");

  script_cve_id("CVE-2020-3330");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs50818");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv110w-static-cred-BMTWBWTy");
  script_xref(name:"IAVA", value:"2020-A-0331");

  script_name(english:"Cisco Small Business RV110W Wireless-N VPN Firewall Static Default Credential (cisco-sa-rv110w-static-cred-BMTWBWTy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by default
static credential vulnerability. Due to a vulnerability in the Telnet service of Cisco Small Business RV110W Wireless-N
VPN Firewall Routers could allow an unauthenticated, remote attacker to take full control of the device with a
high-privileged account.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv110w-static-cred-BMTWBWTy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11ecf258");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs50818");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs50818");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3330");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(798);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:small_business_router");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Device");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business RV Series Router Firmware');
vuln_ranges = [ {'min_ver':'0.0', 'fix_ver':'1.2.2.8'} ];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs50818'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  models:make_list('RV110W')
);
