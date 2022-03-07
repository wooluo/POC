##
# 
##

include('compat.inc');

if (description)
{
  script_id(146596);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2021-26933");
  script_xref(name:"IAVB", value:"2021-B-0011");

  script_name(english:"Xen Scrubbed Pages Cache Information Disclosure (XSA-364)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by an 
information disclosure vulnerability. On Arm, a guest is allowed to control whether memory access bypass the cache. This
means that Xen needs to ensure that all writes (such as the ones during scrubbing) have reached memory before handing
over the page to a guest. Unfortunately the operation to clean the cache happens before checking if the page was
scrubbed. Therefore there is no guarantee when all the writes will reach the memory. A malicious guest may be able to
read sensitive data from memory that previously belonged to another guest.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-364.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26933");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

fixes['4.9']['fixed_ver']           = '4.9.99';
fixes['4.9']['fixed_ver_display']   = 'See vendor advisory';
fixes['4.9']['affected_ver_regex']  = "^4\.9\.";

fixes['4.10']['fixed_ver']           = '4.10.99';
fixes['4.10']['fixed_ver_display']   = 'See vendor advisory';
fixes['4.10']['affected_ver_regex']  = "^4\.10\.";

fixes['4.11']['fixed_ver'] = '4.11.4';
fixes['4.11']['fixed_ver_display'] = '4.11.4 (changeset 80cad58)';
fixes['4.11']['affected_ver_regex'] = "^4.11.";
fixes['4.11']['affected_changesets'] = make_list('1c7d984', 'f9090d9',
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

fixes['4.12']['fixed_ver'] = '4.12.4';
fixes['4.12']['fixed_ver_display'] = '4.12.4 (changeset 4cf5929)';
fixes['4.12']['affected_ver_regex'] = "^4.12.";
fixes['4.12']['affected_changesets'] = make_list('8d26cdd', 'f1f3226',
'cce7cbd', '2525a74', 'c8b97ff', '2186c16', '51e9505', '4943ea7',
'3c13a87', 'd4b884b', '7da9325', 'd6d3b13', '9fe89e1', 'd009b8d',
'674108e', 'bfda5ae', '551d75d', '5e1bac4', 'f8443e8', '655190d',
'f860f42', '9f73020', 'aeebc0c', 'f1a4126', 'b1efedb', '4739f79',
'0dbcdcc', '444b717', '544a775', 'c64ff3b', '8145d38', '14f577b',
'40ab019', '1dd870e', '5c15a1c', '6602544', '14c9c0f', 'dee5d47',
'7b2f479', '46ad884', 'eaafa72', '0e6975b', '8e0c2a2', '51eca39',
'7ae2afb', '5e11fd5', '34056b2', 'fd4cc0b', '4f9294d', '97b7b55');

fixes['4.13']['fixed_ver'] = '4.13.3';
fixes['4.13']['fixed_ver_display'] = '4.13.3-pre (changeset ab995b6)';
fixes['4.13']['affected_ver_regex'] = "^4.13.";
fixes['4.13']['affected_changesets'] = make_list('e416193', '1dd5645',
'bbce51a', '95b5283', 'dc36f72', '0c78a9d', '10c7c21', 'bb534d6',
'16d0dc0', '13afcdf', 'd39eb6f', 'a2f7ae1', 'd6a55f1', 'c6196ca',
'18c0abb', '782aa4b', '6aea4d8', '12a41a8', '4056c3e', 'f4d84a2',
'65c187f', '2df79ff', 'b693968', '52a0a8f', '60e3727', '8cc0a86',
'ef765f6', 'b8f23da', 'ee416da', '1819c9d', '1ab192f', '2007c63',
'2948458', '4959626', '2fa586c', 'b530227', '74c5729', 'a1d8a6c',
'd064b65', '4f30743', '72031bc', '7d6f52d', 'ec09215');

fixes['4.14']['fixed_ver'] = '4.14.2';
fixes['4.14']['fixed_ver_display'] = '4.14.2-pre (changeset 9f357fe)';
fixes['4.14']['affected_ver_regex'] = "^4.14.";
fixes['4.14']['affected_changesets'] = make_list('4170218', '9028fd4',
'7f99c05', 'cad784f', 'e44321d', 'a3509dc', '5f9b0f9', 'a514c5e', '1b09f3d');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_WARNING);
