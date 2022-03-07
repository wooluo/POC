#TRUSTED 03fa651c7bf9c888fdb999f7bdea0f1dd0e3bf85096fea2c0b32449e8711fdf1ef992facfe900065741c6a27f327cfc0160728fb0012823457a07a2e83f597662ba636c39bc0634546360080e8188e31a6ce95b8fa209d4767505c0b7732c63496721e0133ad36ced79ab8d2e263b12461901e0f5dc9a4b634e4eb34dc7acf9188e49dea8c094fdad797fd3dddab886670558c9dd91d1907e4f1aed816e137d6dc7e2896322fb6ddea1b474b86f037c71d843fab7bffcf1dff3cefd16309d8e9c8cfbe9c6e8cdbecd8822d48ef2c7f157f972be532e107964d9a1f328b1bb0620776333af254f5f3d024fcd087426763c3aca87a5042dcce29679a43ba06cd0934143a1fe0f832dd61173d1e82b44950229f91518beb689a88c87a7eb5bd476c3018ac0e694e5c1633f9e72e58bf7a46e188fd97840f1dc06661ff5e9ebb8e90ea2133d39efa6155a8d11c4f59b36975e79619684026f89c5aa97995be7235e1d7256cfad006bcf9bfe38678be4e85c8833c8042bcfbd8f280786c80a9c2f95cbbe4a084a6a2e7a16347b4aaf86c3e962f0cf7954b8f9b8719813df68604e67507f274ee0424e59c2bf75688039524861fbc27952ea906b472c9a4f7ead2c12ce1f05e43340b5809e31c301805cba7ea14823ee393b73be65af2a8d5d4423a3a5d26e19d79023434491727ab1620dd14b3d5453691df2b534288b03656e3a305
#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124589);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/03 13:53:30");

  script_cve_id("CVE-2019-1743");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvi48984");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190327-afu");

  script_name(english:"Cisco IOS XE Software Arbitrary File Upload Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the web UI framework of
Cisco IOS XE Software could allow an authenticated, remote attacker to make unauthorized changes to the filesystem of the
affected device.The vulnerability is due to improper input validation. An attacker could exploit this vulnerability by
crafting a malicious file and uploading it to the device. An exploit could allow the attacker to gain elevated privileges
on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-afu
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi48984");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi48984");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1743");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on vendor advisory");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
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

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , make_list("CSCvi48984")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
