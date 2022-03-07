##
# 
##

include('compat.inc');

if (description)
{
  script_id(149088);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/30");

  script_cve_id("CVE-2020-29479");

  script_name(english:"Xen oxenstored Bad Permissions (XSA-353)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by a bad
permissions issue. In the Ocaml xenstored implementation, the internal representation of the tree has special cases for
the root node, because this node has no parent. Unfortunately, permissions were not checked for certain operations on
the root node. Unprivileged guests can get and modify permissions, list, and delete the root node. (Deleting the whole
xenstore tree is a host-wide denial of service.) Achieving xenstore write access is also possible. All systems using
oxenstored are vulnerable. Building and using oxenstored is the default in the upstream Xen distribution, if the Ocaml
compiler is available. Systems using C xenstored are not vulnerable.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-353.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29479");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
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

fixes['4.10']['fixed_ver']           = '4.10.4';
fixes['4.10']['fixed_ver_display']   = '4.10.4 (changeset e8231b6)';
fixes['4.10']['affected_ver_regex']  = "^4\.10([^0-9]|$)";
fixes['4.10']['affected_changesets'] = make_list('1d72d99', '8eb5328',
  'f79f47f', 'f91d2a9', '1fdcfdb', '17ec9b4', '15b2980', '398f91c',
  '5114e77', '7a4ec79', '78d903e', '2012db4', '71da63b', '56f8da7',
  'd73e972', '6f012ec', '75a05da', 'c334b87', '07ad8ff', '1719f79',
  'f58caa4', 'f2befb6', '83b7f04', 'e081568', '7f0793a', '8fac37e',
  'baf80b6', '5402540', 'f85223f', '635ae12', '3d14937', '4218b74',
  '93be943', '4418841', 'd9c67d3', '8976bab', '388e303', '0b0a155',
  '9df4399', 'fd57038', 'a9bda69', 'a380168', 'c1a4914', '6261a06',
  'fd6e49e', 'bd20589', 'ce05683', '934d6e1', '6e636f2', 'dfc0b23',
  '2f83654', 'bf467cc', '6df4d40', 'e20bb58', 'a1a9b05', 'afca67f',
  'b922c44', 'b413732', '3d60903', 'b01c84e', '1e722e6', '59cf3a0',
  'fabfce8', 'a4dd2fe', '6e63a6f', '24d62e1', 'cbedabf', '38e589d',
  'a91b8fc', '3e0c316', '49a5d6e', '6cb1cb9', 'ba2776a', '9d143e8',
  'fe8dab3', '07e546e', 'fefa5f9', 'c9f9ff7', '406d40d', 'e489955',
  '37139f1', 'fde09cb', '804ba02', 'e8c3971', 'a8c4293', 'aa40452',
  '1da3dab', 'e5632c4', '902e72d', '6a14610', 'ea815b2', '13ad331',
  '61b75d9', 'e70e7bf', 'e966e2e', 'dfa16a1', 'a71e199', 'c98be9e',
  'a548e10', 'd3c0e84', '53b1572', '7203f9a', '6d1659d', 'a782173',
  '24e90db', '0824bc6', 'e6f3135', '3131bf9');

fixes['4.11']['fixed_ver']           = '4.11.4';
fixes['4.11']['fixed_ver_display']   = '4.11.4 (changeset d2b6bf9)';
fixes['4.11']['affected_ver_regex']  = "^4\.11([^0-9]|$)";
fixes['4.11']['affected_changesets'] = make_list('41a822c', '8ab4af9',
  '4fe1326', '4438fc1', '2a730d5', '62aed78', '1447d44', '3b5de11',
  '65fad0a', 'b5eb495', 'e274c8b', '1d021db', '63199df', '7739ffd',
  '4f35f7f', '490c517', '7912bbe', 'f5ec9f2', 'ad7d040', '3630a36',
  '3263f25', '3e565a9', '30b3f29', '3def846', 'cc1561a', '6e9de08',
  '13f60bf', '9703a2f', '7284bfa', '2fe163d', '2031bd3', '7bf4983',
  '7129b9e', 'ddaaccb', 'e6ddf4a', 'f2bc74c', 'd623658', '37c853a',
  '8bf72ea', '2d11e6d', '4ed0007', '7def72c', '18be3aa', 'a3a392e',
  'e96cdba', '2b77729', '9be7992', 'b8d476a', '1c751c4', '7dd2ac3',
  'a58bba2', '7d8fa6a', '4777208', '48e8564', '2efca7e', 'afe82f5',
  'e84b634', '96a8b5b');

fixes['4.12']['fixed_ver']           = '4.12.4';
fixes['4.12']['fixed_ver_display']   = '4.12.4 (changeset c64ff3b)';
fixes['4.12']['affected_ver_regex']  = "^4\.12([^0-9]|$)";
fixes['4.12']['affected_changesets'] = make_list('8145d38', '14f577b',
  '40ab019', '1dd870e', '5c15a1c', '6602544', '14c9c0f', 'dee5d47',
  '7b2f479', '46ad884', 'eaafa72', '0e6975b', '8e0c2a2', '51eca39',
  '7ae2afb', '5e11fd5', '34056b2', 'fd4cc0b', '4f9294d', '97b7b55');

fixes['4.13']['fixed_ver']           = '4.13.3';
fixes['4.13']['fixed_ver_display']   = '4.13.3-pre (changeset 2fa586c)';
fixes['4.13']['affected_ver_regex']  = "^4\.13([^0-9]|$)";
fixes['4.13']['affected_changesets'] = make_list('b530227', '74c5729',
  'a1d8a6c', 'd064b65', '4f30743', '72031bc', '7d6f52d', 'ec09215');

fixes['4.14']['fixed_ver']           = '4.14.1';
fixes['4.14']['fixed_ver_display']   = '4.14.1-pre (changeset f130d5f)';
fixes['4.14']['affected_ver_regex']  = "^4\.14([^0-9]|$)";
fixes['4.14']['affected_changesets'] = make_list('1d1d1f5', '72bd989',
  '8e6c236', '1cfb9b1', '7c6ee4e', 'd11d977', '1ad1773', '0057b1f',
  'd101b41', 'd95f450', '73a0927', 'a38060e', '78a53f0', '89ae1b1',
  '7398a44', '59b8366', '1f9f1cb', 'f728b2d', '71a12a9', '0c96e42',
  '29b48aa', 'd131310', '7d2b21f', 'f61c5d0', 'fc8fab1', '898864c',
  '9f954ae', '5784d1e', '10bb63c', '941f69a', '7b1e587', 'ee47e8e',
  '4ba3fb0', 'd2ba323', 'b081a5f', 'e936515', '9c1cc64', '829dbe2',
  '8d14800', '0521dc9', '64c3951', '0974e00', 'a279fcb', 'f7ab0c1',
  '7339975', '94c157f', '79f1701', '9e757fc', '809a70b', 'b427109',
  'c93b520', 'f37a1cf', '5478934', '43eceee', '03019c2', '66cdf34',
  'ecc6428', '2ee270e', '9b9fc8e', 'b8c2efb', 'f546906', 'eb4a543',
  'e417504', '0bc4177', '5ad3152', 'fc8200a', '5eab5f0', 'b04d673',
  '28855eb', '174be04', '158c3bd', '3535f23', 'de7e543', '483b43c',
  '431d52a', 'ceafff7', '369e7a3', '98aa6ea', '80dec06', '5482c28',
  'edf5b86', 'eca6d5e', 'c3a0fc2', '864d570', 'afed8e4', 'a5dab0a',
  'b8c3e33', 'f836759');

fixes['4.15']['fixed_ver']           = '4.15';
fixes['4.15']['fixed_ver_display']   = '4.15-unstable (changeset feeafa0)';
fixes['4.15']['affected_ver_regex']  = "^4\.15([^0-9]|$)";
fixes['4.15']['affected_changesets'] = make_list('8e0fe4f', 'a69583c',
  '777e359', '0919030', '4b0e0db', '881966d', '841f660', 'd5ce1f6',
  '30d430b', '3ec53aa', '826a6dd', 'd218fb1', 'b7c3330', 'e373bc1',
  '5e66635', 'a00b271', 'bfc78f7', '1e83722', '948719f', '30d3cc4',
  '9afa867', 'b412468', '3a3f4f0', '728acba', '33c1a1c', '905d931',
  'c811706', '7c8946d', '0fb6dbf', 'be3755a', 'f1b920b', 'd290337',
  'ba6e78f', '8be06d7', 'aec4688', 'cabf60f', 'b2a88b2', '1283ad8',
  '9f5ce6e', 'b00d057', '3ae469a', '71ac522', '43803dc', 'f7d7d53',
  'f7e77e5', 'fcdb988', '25ccd09', '181f2c2', '500516f', '8041317',
  '758fae2', '1e6d7bd', 'fd7479b', '9b156bc', '8147e00', '2291ad4',
  '510cdda', 'f390941', '8b6d55c', '6befe59', '1277cb9', 'b659a5c',
  '846d22d', 'dee7d98', 'bebb491', '318a917', '0ff2c7e', '9a3c25b',
  '1965c17', '415f904', '7872b49', '22e323d', '5200fba', '2743174',
  '665c940', 'f2c620a', 'dc5616e', 'a7ab52f', '7aa7629', '192b45e',
  '5505f5f', '6963422', '53bacb8', '628e1be', 'e6e85b6', 'f5cfa09',
  'db1a9fd', 'b5ad37f', '5f2df45', '3059178', '0a5e0ce', 'cd800ce',
  '4196b15', '8aac8e0', '2a5f9f6', 'e19bcb6', 'c3453a2', '957708c',
  'e006b2e', '2b8314a', '9ff9705', 'c0d3cc9', '5816d32', '8587160',
  '7056f2f', '9c2bc0f', 'dac867b', '4d625ff', '1c4aa69', 'ca56b06',
  'b1b4f95', '177cf86', 'a780b17', 'e0daa27', '92bc186', '0b84131',
  '8ac7e45', '6e2ee3d', '82c0d3d', 'f9179d2', '26a8fa4', '1fd1d4b',
  '33d2bad', '16a2096', '055e1c3', '964781c', '20cd1be', '2a75837',
  '92abe14', '4ddd649', '06f0598', '9af5e2b', '588756d', '4664034',
  '154137d', 'f899554', '56c1aca', '70cf8e9', '032a96e', '6ca7082',
  '710f62c', 'b76c3a1', '451a909', '5bc8428', 'dcbd1d8', '83432ad',
  'f9c53bd', 'ba45ae4', '861f0c1', '3b49791', 'aace546', '0514a3a',
  '3b05512', '73f62c7', '5777a37', 'dea460d', '1ce75e9', 'b733f8a',
  '08e6c6f', 'a7f0831', 'de6d188', '7b36d16', '25467bb', '0dfddb2',
  '17d192e', '40fe714', 'a7952a3', '04182d8', '6065a05', '6ee2e66',
  '27addcc', 'a8a85f0', '44ac57a', 'f776e5f', '884ef07', 'e3daad6',
  'f14a422', '6280558', '8752485', '6a34e67', '01d687c', 'c02fd5b',
  '3d77849', 'edc8d91', '47654a0', '8ea798e', '9e5a9d0', 'a95f313',
  'c60f9e4', '534b3d0', '1b810a9', '8a62dee', '8a71d50', '4dced5d',
  '04be2c3', 'afef392', '8d25560', '25849c8', '0241809', 'a06d3fe',
  '1d246c7', '90c9f9f', '5144222', 'fa06cb8', 'c65687e', '7a519f8',
  'e4e6440', '9350859', '7f66c0d', '30bfa53', '1bc30c0', '35679b2',
  '345fd6d', '3600118', 'f5bdb4a', 'dbe399b', '45264e0', '346b115',
  '8ef6345', '9ae1197', '59b27f3', '661b3e4', '6f6f07b', 'bb3d31e',
  '52e1fc4', '22b08b3', '23d4e0d', 'bdb380e', '7f186b1', '77a0971',
  '3ae0d31', 'b22b9b9', 'bc01c73', '41aea82', 'de16a8f', '707eb41',
  '6df07f9', '11852c7', 'bfcc97c', '50a5215', '27de84d', '0d8d289',
  'c739528', 'd72d615', 'e301a70', 'd4bfa0c', 'f60ab53', '5dba8c2',
  'cbe69ba', 'fca8d65', 'ecc9553', 'b18b880', '358d57d', '7c6084c',
  'c8b2488', '1e15dcf', '5be4ce0', '32a9ecc', '28804c0', 'f679038',
  '4bdbf74', '28fb8cf', 'f9ffd20', 'fe41405', '643e2f3', '5bcac98',
  '61d4a04', 'af3c913', '5a37207', 'a673280', '2785b2a', '8fe7b5f',
  'e045199', 'c0ddc86', '8d385b2', '62bcdc4', '112992b', '910093d',
  'e59ce97', 'beb5459', 'cb5e973', '8e76aef', '42317de', 'e71301e',
  '68a8aa5', '0229adb', 'b5622eb', '3eef6d0', 'dd2cfba', 'd4ed1d4',
  '5b61948', '6edcdb4', 'c7e3021', '5164e44', '18063d6', 'baa4d06',
  'c729d54', '5a15c8a', '414d22c', '5152657', '84e848f', '322ec7c',
  '8a31c25', '39ab598', 'a4cbe0f', 'b807cfe', 'fc4e79c', 'd16467b',
  '4f9a616', 'ed7cbd5', 'c8099e4', '6c5fb12', '5d45eca', 'b4e41b1',
  '0fcfe9d', 'e5a1b6f', 'c9476c4', '899316e', 'cc13835', '8900286',
  'ba65a2f', '8efa465', '033b534', 'a4c4b28', '6d2f1eb', '17f80e7',
  '5499e0f', '3cccdae', 'b72aa39', '82651ae', '0ca1af6', 'e69a56b',
  '3df903e', '6d0ec05', '8ab2429', 'dd33fd2', 'e3dd624', 'af6c78d',
  '30f5e8a', '725588c', '7e0165c', '068000a', '256920d', 'f558931',
  '735749c', '6797d1e', '45397d4', '790f2df', 'a547703', '76020cc',
  '0c293ad', 'bb2ea7f', '7c273ff', '0b77395', '52dbd6f', '1e2d3be',
  'b119100', '71039ed', '1be24cd', 'ad0fd29', 'a5eaac9', 'f5b4426',
  '2454fa4', 'e527161', 'f4c1a54', '968bb86', '1814a62', '82c3d15',
  'ac7a21c', 'fc4b1cb', '2c8fabb', '7dcf89d', '696c273', 'a609b65',
  '4d7bcd1', '7dcd33d', '9d207b8', '0dd40d6', 'c9e88d2', '4175fd3',
  '8cf2250', 'afe018e', 'e464742', 'd400dc5', '8d99080', '0de9cbf',
  'ddb2934', 'ded08cd', '09bf291', '097b6fe', 'bc44e2f', '725ef89',
  '314d8cc', 'e32605b', '70c52c4', '484fca9', '812c8e0', 'c7c6de0',
  '22cdff9', 'b51715f', 'bb13d93', '70fea87', 'f9d25fa', 'fff1b7f',
  'd25cc3e', 'a623841', '86c076f', 'd277004', '8b5b49c', 'a156887',
  'de58ea4', '8856a91', '7a8d8bd', '1379576', 'de94e8b', '3473843',
  'c297c94', 'e8f9d21', '888dd66', 'ca7c88e', '858c0be', '3b418b3',
  'f9d6734', '46a5f4f', 'a825751', 'ba28efb', 'feab5bd', '80a868f',
  'ba02a2c', '4d5b209', 'eee588b', '79c2d51', 'f0f2344', 'd501ef9',
  '2404e59', '9c7ff81', '529527b', '7207c15', '74ac7c8', '438c5ff',
  'c4bdb64', '15bc9a1', 'e0f25d1', '9ce2bef', 'beb105a', '391a8b6',
  'e44d986', '47b0bf1', '7a4dd36', '90c7eee', '16dcc13', 'd87c516',
  '5132a0a', 'b2bc1e7', 'dae7ea5', 'a8ee9c4', 'b4175c6', 'e58a712',
  '062aad5', '96137cf', '6156cfe', '067e7b7', '3cb82fe', '5e6dc9b',
  'd9dad35', '37b7b15', 'df8fb11', '2e98d0b', '4866056', '21de968',
  'c9f9a72', 'fe49938', '9909532', '81fd0d3', 'ca24b2f', 'b6a907f',
  '132ece5', 'cb79dc1', 'a85f67b', '98bed5d', '64219fa', 'b071ec2',
  'b6641f2', 'b9e9ccb', 'dc036ab', 'ab5bfc0', '4489ffd', '1ee1441',
  '8899a28', 'c27a184', '0562cbc', 'b2a6429', '82cba98', '55f8c38',
  '8a7bf75', 'ffe4f0f', '26707b7', 'f3885e8', '69953e2', '057cfa2',
  'a6ed77f', '6d49fbd', 'af05849', '139ce42', 'fc7f700', 'f6b78ae',
  '5fd152e', 'ef3b0d8', 'ded576c', '9ffdda9', '6720345', '5a4a411',
  '8c4532f', '6b6f064', 'fb024b7', '1745806', '32fa4ec', '83bb55f',
  '859447a', 'bf2a0ed', 'f8fe3c0', '1969576', 'f36f4bf', '165f3af', '3df0424');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_HOLE);
