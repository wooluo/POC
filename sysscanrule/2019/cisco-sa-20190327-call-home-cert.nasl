#TRUSTED 0de83d9fbfe0658deb06402cbf281db623688f6d5ccf38b314e1f88250fb880d4a396d555d9bb3d33722bea3a87414544d3f811a77ff7c119a5464e91f75eaeb24c05a1c4f57ed2edb94d097ac6bc68b0c6f30d08131f7c8181cc2b9675bdba322617273dce06ea9bdd98bb24a57784e0e3ecdeb62e85a403471597ecc566a4b4a91dd63738c8129a6232f67b15d66acfc6089acd08742de28630c983c19388d13827b0f6b5d8c0d9029a92994c7450a358655a99c4257b7c187fff4ff09c0ad5837e6b92b14b63f73aadfe7240e0b04f30740db62098dbd0880a902af450e52bea370d6557ceab954282ca5cd657f97080fd0080684920af1413b35369011b161ea528d912000515af2548388ba675194e6577cd87f5d2aa7556ddf460f67bf37a72a1a6c0da6df7fa585c2e8b17a1132305362bf7cf2b43055d4a38d9c1de11408a30832f2250e5e796d6e77260fce4a17acdfdf60abf5c1e9e52938a07db2c7635ddadd844d54280a9fbb2bf9fc29aaf124b019b708a639977ef2a9a3e3fa3f944a47a6116be79760d0a69e0bdb8537031a81afacb9bf6e5e141b9fb58c36de79074241ede59588075f7819e53ba1c6ce507597fbe327b51d43eee16c87acea21d10b2c4d0da62f905c021d554bc53154423095a8fa3e572f1e9f6439197bd2a0ea3f49f83d2c1c00c958b977ce0557c9289a582e8bc01671cbe0121a44e1
#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123790);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/05 17:17:24");

  script_cve_id("CVE-2019-1757");
  script_xref(name: "CWE", value: "CWE-295");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvg83741");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190327-call-home-cert");
  script_xref(name:"IAVA", value:"2019-A-0097");

  script_name(english:"Cisco IOS and IOS XE Software Smart Call Home Certificate Validation Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in the Cisco Smart Call Home feature of
    Cisco IOS and IOS XE Software could allow an
    unauthenticated, remote attacker to gain unauthorized
    read access to sensitive data using an
    invalid certificate.The vulnerability is due to
    insufficient certificate validation by the affected
    software. An attacker could exploit this vulnerability
    by supplying a crafted certificate to an affected device.
    A successful exploit could allow the attacker to conduct
    man-in-the-middle attacks to decrypt confidential
    information on user connections to the affected software.
    (CVE-2019-1757)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-call-home-cert
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg83741");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvg83741");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1757");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list=make_list(
  "3.9.2bE",
  "3.9.2E",
  "3.9.1E",
  "3.9.0E",
  "3.8.6E",
  "3.8.5aE",
  "3.8.5E",
  "3.8.4E",
  "3.8.3E",
  "3.8.2E",
  "3.7.5E",
  "3.7.4E",
  "3.6.8E",
  "3.6.7bE",
  "3.6.7aE",
  "3.6.7E",
  "3.6.6E",
  "3.6.5bE",
  "3.6.5aE",
  "3.6.5E",
  "3.6.4E",
  "3.18.4SP",
  "3.18.4S",
  "3.18.3bSP",
  "3.18.3aSP",
  "3.18.3SP",
  "3.18.3S",
  "3.18.2aSP",
  "3.18.2SP",
  "3.18.2S",
  "3.18.1iSP",
  "3.18.1hSP",
  "3.18.1gSP",
  "3.18.1cSP",
  "3.18.1bSP",
  "3.18.1aSP",
  "3.18.1SP",
  "3.18.1S",
  "3.18.0aS",
  "3.18.0SP",
  "3.18.0S",
  "3.17.4S",
  "3.17.3S",
  "3.17.2S ",
  "3.17.1aS",
  "3.17.1S",
  "3.17.0S",
  "3.16.7bS",
  "3.16.7aS",
  "3.16.7S",
  "3.16.6bS",
  "3.16.6S",
  "3.16.5bS",
  "3.16.5aS",
  "3.16.5S",
  "3.16.4gS",
  "3.16.4eS",
  "3.16.4dS",
  "3.16.4cS",
  "3.16.4bS",
  "3.16.4aS",
  "3.16.4S",
  "3.16.3aS",
  "3.16.3S",
  "3.16.2bS",
  "3.16.2aS",
  "3.16.2S",
  "3.16.1aS",
  "3.16.1S",
  "3.10.1sE",
  "3.10.1aE",
  "3.10.1E",
  "3.10.0cE",
  "3.10.0E",
  "16.9.1s",
  "16.9.1c",
  "16.9.1b",
  "16.8.2",
  "16.8.1s",
  "16.8.1d",
  "16.8.1c",
  "16.8.1b",
  "16.8.1a",
  "16.8.1",
  "16.7.2",
  "16.7.1b",
  "16.7.1a",
  "16.7.1",
  "16.6.3",
  "16.6.2",
  "16.6.1",
  "16.5.3",
  "16.5.2",
  "16.5.1b",
  "16.5.1a",
  "16.5.1",
  "16.4.3",
  "16.4.2",
  "16.4.1",
  "16.3.6",
  "16.3.5b",
  "16.3.5",
  "16.3.4",
  "16.3.3",
  "16.3.2",
  "16.3.1a",
  "16.3.1",
  "16.2.2",
  "16.2.1"
);

workarounds = make_list(CISCO_WORKAROUNDS['section_call-home']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , make_list("CSCvg83741"),
  'cmds'     , make_list("show running-config | section call-home")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
