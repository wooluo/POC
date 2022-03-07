#TRUSTED 56f694b1fea86a045203efc016bc85dc48106e3f434c8fed063489771cc6d09d5d895b32bfc177b88a43c2990a281ce2208322e7fc37fd2098291b95896d2e6ea06f08ca2689cc76e9cd4528a8724e0bf8d0611047822bc93216a0cc5508b73f8d1f8440b9d0102d34a90959d0514925ec4c35ebbf7cbc395e827e459170e57da52c10f9b8168d71bcb5bf5fd2ac47c214fb993d3260b33a1f080fa09712e27bb2798448dbeb49146db12bbd348093cf18f905e227a6eccc0b73a25378103c43475afa4c8c550010bb5b0f413bf3032fb96bc840e9e2c51022668458b908c8e3ff4e7c5f911f2a4e2d89ca0c660aaf6b426f14a67753ab63cae92ba6880a61f2d507387de4d15dd2bc2febc6d6dc87a766ec7c4b31a6474940528345edcfa7f6dd2a82b699ee382d889be41bbf5015d562cc7cef62169eb8877447f39b4fe5b414ab896aa34b6850a618ef7bce130a21866eab047d07a14238f5c21292834391d887ae10ded6d23dee0241eec014eb31c68253f1d44640807a5669097fe2323f2242bbe187baf80c6d318ebb21623d14379206527fcd0a4dc93d83999cb23ba47f86b30886cde395197be8584970059acd84839473114d198653ca6bcf6b7b76b9c95c9395e81f313ecc41bb890ddab5b9115121d8f9dd2fdaafaf8dd84ebe46e57f291fbc37d182208999b65ca68009b63903c0d47f969134df6cca6c850b73
#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123793);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/05 17:17:24");

  script_cve_id("CVE-2019-1759");
  script_xref(name: "CWE", value: "CWE-284");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvk47405");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190327-mgmtacl");
  script_xref(name:"IAVA", value:"2019-A-0097");

  script_name(english:"Cisco IOS XE Software Gigabit Ethernet Management Interface Access Control List Bypass Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in access control list (ACL)
    functionality of the Gigabit Ethernet Management
    interface of Cisco IOS XE Software could allow an
    unauthenticated, remote attacker to reach the configured
    IP addresses on the Gigabit Ethernet Management
    interface.The vulnerability is due to a logic error that
    was introduced in the Cisco IOS XE Software 16.1.1
    Release, which prevents the ACL from working when
    applied against the management interface. An attacker
    could exploit this issue by attempting to access the
    device via the management interface. (CVE-2019-1759)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-mgmtacl
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk47405");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk47405");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1759");

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
  "16.9.2",
  "16.9.1s",
  "16.9.1d",
  "16.9.1c",
  "16.9.1b",
  "16.9.1a",
  "16.9.1",
  "16.8.2",
  "16.8.1s",
  "16.8.1e",
  "16.8.1d",
  "16.8.1c",
  "16.8.1b",
  "16.8.1a",
  "16.8.1",
  "16.7.2",
  "16.7.1b",
  "16.7.1a",
  "16.7.1",
  "16.6.4s",
  "16.6.4a",
  "16.6.4",
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
  "16.3.7",
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

workarounds = make_list(CISCO_WORKAROUNDS['acl_on_gigabit_ethernet_management_interface']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , make_list("CSCvk47405"),
  'cmds'     , make_list("show running-config | section interface GigabitEthernet0$")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
