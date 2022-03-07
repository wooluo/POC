#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124030);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/15  5:04:12");

  script_cve_id("CVE-2019-0043");

  script_name(english:"Juniper JSA10935");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to
tested version. It is, therefore, affected by a vulnerability as
referenced in the JSA10935 advisory. Note that GizaNE has not tested
for this issue but has instead relied only on the application's self-
reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/KB16613");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/KB16765");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/KB16446");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10935");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10935");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0043");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
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

if (model =~ "^SRX")
  fixes["12.1X46"] = "12.1X46-D77";
fixes["12.3"] = "12.3R12-S10";
if (model =~ "^SRX")
  fixes["12.3X48"] = "12.3X48-D75";
if (model =~ "^(EX|QFX)")
  fixes["14.1X53"] = "14.1X53-D48";
fixes["15.1"] = "15.1R4-S9";
fixes["15.1F"] = "15.1F6-S11";
if (model =~ "^SRX")
  fixes["15.1X49"] = "15.1X49-D141";
if (model =~ "^(QFX52|QFX511)")
  fixes["15.1X53"] = "15.1X53-D234";
if (model =~ "^QFX1")
  fixes["15.1X53"] = "15.1X53-D68";
if (model =~ "^NFX")
  fixes["15.1X53"] = "15.1X53-D471";
if (model =~ "^(EX23|EX34)")
  fixes["15.1X53"] = "15.1X53-D590";
fixes["16.1"] = "16.1R3-S10";
fixes["16.1X65"] = "16.1X65-D48";
fixes["16.2"] = "16.2R2-S6";
fixes["17.1"] = "17.1R2-S8";
fixes["17.2"] = "17.2R1-S7";
fixes["17.2X75"] = "17.2X75-D102";
fixes["17.3"] = "17.3R3";
fixes["17.4"] = "17.4R1-S4";
fixes["18.1"] = "18.1R1-S1";
fixes["18.2X75"] = "18.2X75-D10";

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
