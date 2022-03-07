#TRUSTED af98329a8c985221401fb02be50833c0947920efebd470ff42033cee820450228a58f9c691c4b819f834e31145ce8be050c55db9fb6fcc757622372ec249640b5e83708aa160e87b034073d559dd08b1facf83c87a62a58a51b2fe8ce7ca4d95254245ebe0b0ba24c9e92a2970c19638b6df557daad2b5692ab62a2eb1951f21e58912ef605c1a9673c6b1dd5c87ea3629552bcc906eb205e3ad1dc8e864deb05b333c689fe7d8c5fdf40fb06d1f8b9a61ee4171498652d13203d4457cc8402ab8664ad1d50913e50f975479742cc9501f9873d5476200e986fe114df871a97a11b5546d5964cc993612719c08f1d87773f89cab1311b33dd98497b55969302ea55d7d14afa10273ca73dc5bf461763a50c6ee6900fd0d07933e041a9399c51486c41e5194fb1533b648378ba8b6ef084f9d5662b49917dcdfec56b940847ead2a7f57f0e174c9a1b995171ee6f8501a60a7a5d41756070093675f78b63fa3b9a303c1f8c1463fa63d8d024c198b00f6da0ebb3b8b7c6a13be42ebc94d85b07a581982b787a4ef9de582a4dfae864c36b0d0611e9d39cd8d8338c9a2ab74259dea2484b1978313cf742848030b27d5f6a517352ddca261e092226d793de6cbc6e0fb3590e482a78aad56a21440b4646650705c097b66aa7e9d195ba848cc9c6051946731911852160bab120463dd83bbf15ef4351136ea4dd039b0b65e664d8b
#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123795);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/05 17:17:24");

  script_cve_id("CVE-2019-1760");
  script_xref(name: "CWE", value: "CWE-20");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvj55896");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190327-pfrv3");
  script_xref(name:"IAVA", value:"2019-A-0097");

  script_name(english:"Cisco IOS XE Software Performance Routing Version 3 Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in Performance Routing Version 3 (PfRv3)
    of Cisco IOS XE Software could allow an unauthenticated,
    remote attacker to cause the affected device to
    reload.The vulnerability is due to the processing of
    malformed smart probe packets. An attacker could exploit
    this vulnerability by sending specially crafted smart
    probe packets at the affected device. A successful
    exploit could allow the attacker to reload the device,
    resulting in a denial of service (DoS) attack on an
    affected system. (CVE-2019-1760)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-pfrv3
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj55896");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvj55896");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1760");

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
  "16.8.1s",
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
  "16.3.2"
);

workarounds = make_list(CISCO_WORKAROUNDS['pfrv3']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , make_list("CSCvj55896"),
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
