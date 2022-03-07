#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124193);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/19 13:29:00");

  script_cve_id("CVE-2019-0037");
  script_bugtraq_id(107894);
  script_xref(name:"IAVA", value:"2019-A-0121");

  script_name(english:"Juniper Junos jdhcpd crash denial of service (JSA10926)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a denial of service
vulnerability in the jdhcpd daemon due to failure to handle exceptional conditions. An unauthenticated, remote attacker
can exploit this, via continuously sending a certain DHCPv6 solicit message to the jdhcpd daemon to cause the jdhcpd
process to stop responding.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10926&cat=SIRT_1&actp=LIST&showDraft=false
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10926");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0037");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

fixes["15.1"] = "15.1F6-S12";
fixes["15.1X49"] = "15.1X49-D171";
fixes["15.1X53"] = "15.1X53-D236";
fixes["16.1"] = "16.1R3-S10";
fixes["16.2"] = "16.2R2-S8";
fixes["17.1"] = "17.1R2-S10";
fixes["17.2"] = "17.2R1-S8";
fixes["17.3"] = "17.3R3-S3";
fixes["17.4"] = "17.4R1-S6";
fixes["18.1"] = "18.1R2-S4";
fixes["18.2"] = "18.2R2";
fixes["18.2X75"] = "18.2X75-D30";
fixes["18.3"] = "18.3R1-S2";

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
