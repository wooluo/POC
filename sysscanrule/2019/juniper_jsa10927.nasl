#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124195);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/19 15:32:17");

  script_cve_id("CVE-2019-0038");
  script_bugtraq_id(107873);
  script_xref(name:"IAVA", value:"2019-A-0121");

  script_name(english:"Juniper Junos SRX crafted packets destined to fxp0 denial of service (JSA10927)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a denial of service
vulnerability in the management interface due to buffer space exhaustion. An unauthenticated, adjacent attacker can
exploit this issue, via crafted packets destined to the management interface (fxp0) to cause the service to stop
responding.
");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10927&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10927");

  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0038");

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
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

if (model !~ "^(SRX340|SRX345)") audit(AUDIT_HOST_NOT, "SRX340 or SRX345");

fixes["15.1X49"] = "15.1X49-D160";
fixes["17.4"] = "17.4R2-S3";
fixes["18.1"] = "18.1R3-S1";
fixes["18.2"] = "18.2R2";
fixes["18.3"] = "18.3R1-S2";

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
