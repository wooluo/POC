
##
# 
##



include('compat.inc');

if (description)
{
  script_id(152208);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/05");

  script_cve_id("CVE-2021-28692");
  script_xref(name:"IAVB", value:"2021-B-0044");

  script_name(english:"Xen Inappropriate x86 IOMMU Timeout Detection / Handling (XSA-372)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by a
vulnerability due to inappropriate x86 IOMMU timeout detection / handling IOMMUs process commands issued to them in
parallel with the operation of the CPU(s) issuing such commands. In the current implementation in Xen, asynchronous
notification of the completion of such commands is not used. Instead, the issuing CPU spin-waits for the completion of
the most recently issued command(s). Some of these waiting loops try to apply a timeout to fail overly-slow commands.
The course of action upon a perceived timeout actually being detected is inappropriate: - on Intel hardware guests which
did not originally cause the timeout may be marked as crashed, - on AMD hardware higher layer callers would not be
notified of the issue, making them continue as if the IOMMU operation succeeded.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xenproject.org/xsa/advisory-373.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28692");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("xen_server_detect.nbin");
  script_require_keys("installed_sw/Xen Hypervisor", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app = 'Xen Hypervisor';
app_info = vcf::xen_hypervisor::get_app_info(app:app);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes['4.11']['fixed_ver']           = '4.11.4';
fixes['4.11']['fixed_ver_display']   = '4.11.4 (changeset 944da2f)';
fixes['4.11']['affected_ver_regex']  = "^4\.11\.";
fixes['4.11']['affected_changesets'] = make_list('9f8bf2a', 'dc3e544',
  '89d3cc6', '37518c2', 'b1e46bc', '8bce469', '1d5581d', '9b299ec', 
  '131d98f', 'f4adc4d', 'efe63c5', 'a0ae69c', '04dd325', 'e806708', 
  '4288da8', '939164f', '76d369d', '80cad58', '1c7d984', 'f9090d9', 
  '310ab79', '2d49825', '24f7d03', 'f1f3dee', '1e87058', '4cc2387', 
  '4053771', 'b3f4121', 'e36f81f', '1034a45', '7791d2e', '5724431', 
  '495e973', '771a105', 'b3f80a3', '966f266', '57261ac', '1b7ed67', 
  '0a6bbf9', '6be47ee', '2fe5a55', '36621b7', '88f6ff5', '170445f', 
  '550387f', '0297770', 'd2b6bf9', '41a822c', '8ab4af9', '4fe1326', 
  '4438fc1', '2a730d5', '62aed78', '1447d44', '3b5de11', '65fad0a', 
  'b5eb495', 'e274c8b', '1d021db', '63199df', '7739ffd', '4f35f7f', 
  '490c517', '7912bbe', 'f5ec9f2', 'ad7d040', '3630a36', '3263f25', 
  '3e565a9', '30b3f29', '3def846', 'cc1561a', '6e9de08', '13f60bf', 
  '9703a2f', '7284bfa', '2fe163d', '2031bd3', '7bf4983', '7129b9e', 
  'ddaaccb', 'e6ddf4a', 'f2bc74c', 'd623658', '37c853a', '8bf72ea', 
  '2d11e6d', '4ed0007', '7def72c', '18be3aa', 'a3a392e', 'e96cdba', 
  '2b77729', '9be7992', 'b8d476a', '1c751c4', '7dd2ac3', 'a58bba2', 
  '7d8fa6a', '4777208', '48e8564', '2efca7e', 'afe82f5', 'e84b634', '96a8b5b');

fixes['4.12']['fixed_ver']           = '4.12.4';
fixes['4.12']['fixed_ver_display']   = '4.12.4 (changeset d024fe1)';
fixes['4.12']['affected_ver_regex']  = "^4\.12\.";
fixes['4.12']['affected_changesets'] = make_list('e5f3be9', 'e318c13',
  'ced413b', '95d23c7', 'aa8866c', '2c39570', '5984905', '5b280a5', 
  '955c604', 'cd5666c', '1df73ab', 'b406997', 'f66542f', '26764c5', 
  'b100d3e', '17db0ba', '2e9e9e4', '652a259', 'b8737d2', '70c53ea', 
  '4cf5929', '8d26cdd', 'f1f3226', 'cce7cbd', '2525a74', 'c8b97ff', 
  '2186c16', '51e9505', '4943ea7', '3c13a87', 'd4b884b', '7da9325', 
  'd6d3b13', '9fe89e1', 'd009b8d', '674108e', 'bfda5ae', '551d75d', 
  '5e1bac4', 'f8443e8', '655190d', 'f860f42', '9f73020', 'aeebc0c', 
  'f1a4126', 'b1efedb', '4739f79', '0dbcdcc', '444b717', '544a775', 
  'c64ff3b', '8145d38', '14f577b', '40ab019', '1dd870e', '5c15a1c', 
  '6602544', '14c9c0f', 'dee5d47', '7b2f479', '46ad884', 'eaafa72', 
  '0e6975b', '8e0c2a2', '51eca39', '7ae2afb', '5e11fd5', '34056b2', 
  'fd4cc0b', '4f9294d', '97b7b55');

fixes['4.13']['fixed_ver']           = '4.13.4';
fixes['4.13']['fixed_ver_display']   = '4.13.4-pre (changeset ddb3edb)';
fixes['4.13']['affected_ver_regex']  = "^4\.13\.";
fixes['4.13']['affected_changesets'] = make_list('e39050c', '235bfe8',
  '84bc28f', '9eece40', '2c9da5f', '5aacd07', '64752a9', '948b7c8', 
  '9bd6416', '97af34f', 'f799329', '0a3eb9b', 'd3d8a29', '83c0f6b', 
  '9e3c8b1', 'def4352', '95197d4', 'ef8b235', 'f17d848', 'fa5afbb', 
  '4d54414', '287f229', 'e289ed6', '2841329', '33049e3', '53f4ce9', 
  '8113b02', '0e711a0', '21e1ae3', '4352a49', 'e93d278', '231237c',
  'ca06bce', '5aef2c5', '5de1558', 'e3bcd4d');

fixes['4.14']['fixed_ver']           = '4.14.3';
fixes['4.14']['fixed_ver_display']   = '4.14.3-pre (changeset e06d0c1)';
fixes['4.14']['affected_ver_regex']  = "^4\.14\.";
fixes['4.14']['affected_changesets'] = make_list('1dae9fd', '64d93d6',
  '3ae25fc', '665024b', 'ecd6b17', 'c6ee6d4', 'b6a8c4f', '45710c0', 
  'ee5425c', '4b4ee05', '768138c', '0ff7f9c', 'fcf98ef', '51278ce', 
  '766b1f4', 'e5bce3a', '46ff245', '2665d97', '7053c8e', '5caa690', 
  'b046e05', '3f85493', 'ac507e0', 'ebfdf0c', '9d963a7', 'b15c24a', 
  'f23cb47', 'c2f78b4', 'a351751');

fixes['4.15']['fixed_ver']           = '4.15.1';
fixes['4.15']['fixed_ver_display']   = '4.15.1-pre (changeset 3581714)';
fixes['4.15']['affected_ver_regex']  = "^4\.15\.";
fixes['4.15']['affected_changesets'] = make_list('0b80b34', 'd8a530e',
  '9892901', '3556dc6', '13ea8af', '77069ea', 'ec457ac', '4586e64', 
  '796d405', '0aabeb9', 'a339cea', '874dac9', 'f034c96', '894636d', 
  '12ebf0f', '35b5836', '8368f21', '7044184', '0a64b18', 'eae0dfa', 
  '89c6e84', '7c3c984', '6a7e21a', 'ee2b1d6', 'edeaa04', 'cacad0c', 
  '3e6c1b6', '78a7c3b', '280d472', 'eb1f325', 'dfcce09', 'c129b5f', 
  'e2e80ff', '5788a7e', 'bb071ce', '92dd3b5', 'baa6957', 'c86d8ec', 'e72bf72');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_WARNING);
