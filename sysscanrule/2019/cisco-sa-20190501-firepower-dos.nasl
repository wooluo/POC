#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125256);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/17 16:24:26");

  script_cve_id("CVE-2018-15462", "CVE-2019-1687", "CVE-2019-1694");
  script_bugtraq_id(108160, 108176, 108178);
  script_xref(name: "CISCO-BUG-ID", value: "CSCvf95761");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvg76064");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvk35736");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvk44166");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvn51149");
  script_xref(name: "CISCO-BUG-ID", value: "CSCvn78174");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190501-firepower-dos");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190501-asa-ftdtcp-dos");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190501-asa-frpwrtd-dos");

  script_name(english:"Cisco Firepower Threat Defense Software  6.x < 6.2.3.12 / 6.3.x < 6.3.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Cisco Firepower Threat Defense Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by following vulnerabilities:

  - A vulnerability in the TCP ingress handler for the data interfaces that are configured with management
    access to Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to
    cause an increase in CPU and memory usage, resulting in a denial of service (DoS) condition. The
    vulnerability is due to insufficient ingress TCP rate limiting for TCP ports 22 (SSH) and 443 (HTTPS). An
    attacker could exploit this vulnerability by sending a crafted, steady stream of TCP traffic to port 22 or
    443 on the data interfaces that are configured with management access to the affected device.
    (CVE-2018-15462)

  - A vulnerability in the TCP proxy functionality for Cisco Firepower Threat Defense (FTD) Software could
    allow an unauthenticated, remote attacker to cause the device to restart unexpectedly, resulting in a
    denial of service (DoS) condition. The vulnerability is due to an error in TCP-based packet inspection,
    which could cause the TCP packet to have an invalid Layer 2 (L2)-formatted header. An attacker could
    exploit this vulnerability by sending a crafted TCP packet sequence to the targeted device. A successful
    exploit could allow the attacker to cause a DoS condition. (CVE-2019-1687)

  - A vulnerability in the TCP processing engine of Cisco Firepower Threat Defense (FTD) Software could allow
    an unauthenticated, remote attacker to cause an affected device to reload, resulting in a denial of
    service (DoS) condition. The vulnerability is due to the improper handling of TCP traffic. An attacker who
    is using a TCP protocol that is configured for inspection could exploit this vulnerability by sending a
    specific sequence of packets at a high rate through an affected device. A successful exploit could allow
    the attacker to temporarily disrupt traffic through the device while it reboots. (CVE-2019-1694)

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-firepower-dos
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf95761");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg76064");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk35736");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk44166");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn51149");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn78174");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvf95761, CSCvg76064, CSCvk35736, CSCvk44166,
CSCvn51149, CSCvn78174");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15462");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on vendor advisory");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/show_ver", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

show_ver = get_kb_item_or_exit('Host/Cisco/show_ver');

app = 'Cisco Firepower Threat Defense';

ver = pregmatch(string:show_ver, pattern:"\s*Model\s*:\s+Cisco.*Threat\s+Defense.*Version\s+([0-9.]+)");

if (isnull(ver)) audit(AUDIT_HOST_NOT, app);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = ver[1];

if (ver =~ "^6\.[0-2]\.[0-3]($|\.)")
  fix = '6.2.3.12';
else if (ver =~ "^6\.3\.0($|\.)")
  fix = '6.3.0.3';
else
  audit(AUDIT_INST_VER_NOT_VULN, app, ver);

if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Bug               : CSCvf95761, CSCvg76064, CSCvk35736, CSCvk44166, CSCvn51149, CSCvn78174' +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix;
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
} else audit(AUDIT_INST_VER_NOT_VULN, app, ver);
