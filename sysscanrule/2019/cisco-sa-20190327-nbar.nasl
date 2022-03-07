#TRUSTED 87aaa6bf268fb8df496b1d702711fdfb13d05872c0d96139d76ea91a8d91ad5213af2f5db7883a3086b713ae90ce3d50c1d88edf71163c51234abf156da50f7857e15ce50f989eff51d999d0de7d5ad2e18eaf89c585a5f0dbe7e818f34b499d082efafb878519a03dc637fda105ddc334ac54ef7d18d78779073fec4f97a427c5a7d84126ed28d060130fbeeec1052027a139464eb8159cebc9362859e86d3c57178f906d11c4955dcf26a10becb21081d64cbf2c78de653469cfc201e78a6cf0cfc646c2eb408a5572bb2d16b34613fda0d49333ff14a99841926e575f5488b907675229e20f440af5f9e647fc3bc3096c7de4c4ef87de9d5367d05ac6783dc64327570e4c224b1d4668de387c2a037fb2f6bbe1a0b580b6e20544c5fb35ce4a0b52ca6b7627f01777d76469eb4021f45abbb58a2d31d7dbeee236437b1a72bf6e674127d5d43fc66e57a0c3c5a2e100b483e4671c896f65a914f547dddb6011932df288c8f36d99b342b4c33a8d45b3eb3fd94b2f9f8a11f290779e54d3c57dd4b3fb52323edc447f4c79125f7556cda8bc2c77e8d065eaae2a66e59bc065b202fa1901095826f38417770e898ae06bddbde9a754154b12592c10e40c872a0920ba8537d67989e13056efc5834cbf321f1741517e4754944754e5c39767936f82d05d0f622a1571eddf9580dc24e2f704d3b465d07365c73e35cd32e31220
#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123794);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/05 17:17:24");

  script_cve_id("CVE-2019-1738", "CVE-2019-1739", "CVE-2019-1740");
  script_xref(name: "CWE", value: "CWE-20");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvb51688");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvb51688");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvb51688");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190327-nbar");
  script_xref(name:"IAVA", value:"2019-A-0097");

  script_name(english:"Cisco IOS XE Software Network-Based Application Recognition Denial of Service Vulnerabilities");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following multiple vulnerabilities

  - Multiple vulnerabilities in the Network-Based
    Application Recognition (NBAR) feature of Cisco IOS
    Software and Cisco IOS XE Software could allow an
    unauthenticated, remote attacker to cause an affected
    device to reload.These vulnerabilities are due to a
    parsing issue on DNS packets. An attacker could exploit
    these vulnerabilities by sending crafted DNS packets
    through routers that are running an affected version and
    have NBAR enabled. A successful exploit could allow the
    attacker to cause the affected device to reload,
    resulting in a denial of service (DoS) condition.
    (CVE-2019-1738, CVE-2019-1739, CVE-2019-1740)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-nbar
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb51688");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb51688");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb51688");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCvb51688, CSCvb51688, CSCvb51688");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1738");

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
  "3.18.4S",
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
  "3.16.0cS",
  "3.16.0bS",
  "3.16.0aS",
  "3.16.0S",
  "16.5.1b",
  "16.5.1a",
  "16.5.1",
  "16.4.3",
  "16.4.2",
  "16.4.1",
  "16.3.4",
  "16.3.3",
  "16.3.2",
  "16.3.1a",
  "16.3.1",
  "16.2.2",
  "16.2.1"
);

workarounds = make_list(CISCO_WORKAROUNDS['nbar']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , make_list("CSCvb51688", "CSCvb51688", "CSCvb51688"),
  'cmds'     , make_list("show ip nbar control-plane | include NBAR state")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
