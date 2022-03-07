#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126785);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/18 17:35:54");

  script_cve_id("CVE-2019-0052");
  script_bugtraq_id(109145);
  script_xref(name: "JSA", value: "JSA10946");
  script_xref(name:"IAVA", value:"2019-A-0250");

  script_name(english:"Juniper JSA10946");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is prior to
12.3X48-D85, 15.1X49-D181, 17.4R1-S8, 18.1R3-S6, 18.2R2-S1, 18.3R1-S2,
or 18.4R1-S1. It is, therefore, affected by a vulnerability as
referenced in the JSA10946 advisory. Note that GizaNE has not tested
for this issue but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10946");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10946");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0052");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

if (model =~ "^SRX")
  fixes["12.3X48"] = "12.3X48-D85";
if (model =~ "^SRX")
  fixes["15.1X49"] = "15.1X49-D181";
if (model =~ "^SRX")
  fixes["17.4"] = "17.4R1-S8";
if (model =~ "^SRX")
  fixes["18.1"] = "18.1R3-S6";
if (model =~ "^SRX")
  fixes["18.2"] = "18.2R2-S1";
if (model =~ "^SRX")
  fixes["18.3"] = "18.3R1-S2";
if (model =~ "^SRX")
  fixes["18.4"] = "18.4R1-S1";

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
