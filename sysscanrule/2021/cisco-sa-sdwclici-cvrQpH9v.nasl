#TRUSTED 2f1c7b32cee95c062014100a0cd37f3c0285bd89eb00e38fb78ca3167fd666120c529f3eea7339b34a77919fa0c4a83bcc79098d0a03e2a4b54408a671403d24ee56731ea50bbbb28cbc501000a5b0e211daa948f3dcfb6aad9285171c49bae625f8965d988e848d477e12999a4ff45029fb7aae0544a237ea5f30a23e070a9c16571e321dd8be0f701afd21fd54a1dcf104bccdbddc18d17527d55ed70ca66ffc8a666158fdbf8fc1dc9b6f49d4bf432ab0d486b809c6e6a30b9fbc2fb9e0b1588014e82d1e62a6020ec39f59eef9d4dbaf71e53c5d9841851fc10de6fcd75f47dd5e02f8e09bd32919248a3d53b0e1becdf56941da94acdc9ba791cdbaf970328579735a19be7fc1aabf10eda05be852fb93ba55776b762eadb5c986593db0ccfce87c78a978861a4c533e03678903f1522036d144fb075961d49b8e79af1ea768d67aa38a85ad6cdb99a8f85e44cb6863db3d629e7288c6670918b3547ac833e122b994f6a765a98d16efd6fe137305b5f6b7f33c03d073106042d057db6ac7d7ff1fc173e37944e008b8368d98ee447be456433e38a2b2fd12183555d764f4032c33c69cf2efb7ca7e7699338591d99d56ba086a88ce66247aaa0e36b204c24efa5f1f0f9072f55b4ae02cf8060efacf7b3f3d918b2e9b1a78704d51c6902e03d3953e09c1e0cb9e68392569cc42f6e47d6f3f85e3d1fb1e570d161c85be
##
# 
##

include('compat.inc');

if (description)
{
  script_id(147733);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/12");

  script_cve_id("CVE-2020-3266");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs47126");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwclici-cvrQpH9v");

  script_name(english:"Cisco SD-WAN Solution Command Injection (cisco-sa-sdwclici-cvrQpH9v)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Solution is affected by a command injection vulnerability due to
insufficient input validation. An authenticated, local attacker can exploit this, by authenticating to the device and
submitting crafted input to the CLI utility, in order to inject arbitrary commands.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwclici-cvrQpH9v
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cb97617");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs47126");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs47126");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3266");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
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

if (tolower(product_info['model']) !~ "vbond|vedge|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0', 'fix_ver':'19.2.2' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs47126'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
