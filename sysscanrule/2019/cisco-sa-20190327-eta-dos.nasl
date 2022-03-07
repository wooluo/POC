#TRUSTED 7a09a26117d52eb4d29adddd447ad2dd902992936ebe0d8901a502e1f87b334def7559d6cf322b98e3c49b59bb898239c2e78b0ca51e3beeff645a32074d609b9e3858946bdd30a82a1b2e16455330661cdc0fb4bb1abd309cc3c1803a081be5dc8b3a507c962c2d3a4787af26a41158cc10c7e9a0b427043c5e8cdf42fb233d19f5d80a8c2e41e245c563d24755176f61691ecc1848e4d46bcb3cc239b690ad69f6a451fbc5f0f1937122fb53bbccef47d4ee225682e4e53f0627f790ebb34e06621e9faf184312c618f0640c0c75a032e4ee391de9f8ac48f272cedf7aadf495b55853af88a85056fdc16cb0351db4d6b6608b0e66ec746f981aed892d62673bf0bd7745eddf48c10c2c50be7b85dfce77ae25314bc868872e1b99756b604c7b15b82325fa8bd512f3a29f0abe72db61b86299ecc4508ee0e0ece18aa1356d09d4a203e6330adbcdd2bcdbf9f5428f7b353ace9fdbc7d6089d3cf4bbcd477bd252fef0d741d8616d1e177282aee752d428380164116b6429a5287b921b61dd982516389e50f8bb409f4ef3ffa5ea9acfdae36a5dd81e1fef2a56f8074d1e3f32aa81fb17f4974aeafb0dbfcf938d0ed00e23c1849ff8716c16176187d10ee7930a91033a2c8c187980a1f9e321b0fa3d1699861e7a5ebe725d2c17345dfedc52604b26d87cd8b919e26605e0f26d57f624fab8cd296c8e2a2c26e4f6c8cdc2
#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123791);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/05 17:17:24");

  script_cve_id("CVE-2019-1741");
  script_xref(name: "CWE", value: "CWE-20");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvi77889");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190327-eta-dos");
  script_xref(name:"IAVA", value:"2019-A-0097");

  script_name(english:"Cisco IOS XE Software Encrypted Traffic Analytics Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in the Cisco Encrypted Traffic Analytics
    (ETA) feature of Cisco IOS XE Software could allow an
    unauthenticated, remote attacker to cause a denial of
    service (DoS) condition.The vulnerability is due to a
    logic error that exists when handling a malformed
    incoming packet, leading to access to an internal data
    structure after it has been freed. An attacker could
    exploit this vulnerability by sending crafted, malformed
    IP packets to an affected device. A successful exploit
    could allow the attacker to cause an affected device to
    reload, resulting in a DoS condition. (CVE-2019-1741)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-eta-dos
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi77889");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvi77889");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1741");

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
  "3.2.0JA",
  "16.8.1s",
  "16.8.1e",
  "16.8.1d",
  "16.8.1c",
  "16.8.1b",
  "16.8.1a",
  "16.8.1",
  "16.7.1b",
  "16.7.1a",
  "16.7.1",
  "16.6.3",
  "16.6.2",
  "16.6.1"
);

workarounds = make_list(CISCO_WORKAROUNDS['platform_software_et-analytics_interfaces']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , make_list("CSCvi77889"),
  'cmds'     , make_list("show platform software et-analytics interfaces")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
