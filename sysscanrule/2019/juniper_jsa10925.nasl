#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124031);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/20  6:39:51");

  script_cve_id("CVE-2019-0036");

  script_name(english:"Juniper JSA10925");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to
tested version. It is, therefore, affected by a vulnerability as
referenced in the JSA10925 advisory. Note that GizaNE has not tested
for this issue but has instead relied only on the application's self-
reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/KB16613");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/KB16765");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/KB16446");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10925");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0036");

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
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

if (ver !~ '14.1X53-D49') # not vuln but in same 14.1X53 series
  fixes['14.1X53'] = '14.1X53-D130';

fixes['15.1F'] = '15.1F6-S12';
fixes['15.1R'] = '15.1R7-S4';
fixes['15.1X49'] = '15.1X49-D161'; # or 15.1X49-D170
fixes['15.1X53'] = '15.1X53-D236'; # or 15.1X53-D496
fixes['16.1'] = '16.1R7-S4';
fixes['16.2'] = '16.2R2-S9';
fixes['17.1'] = '17.1R3';

if (ver =~ "^17\.2R1")
  fixes['17.2R'] = '17.2R1-S8';
else
  fixes['17.2R'] = '17.2R4-S1';

fixes['17.3'] = '17.3R3-S4';
fixes['17.4'] = '17.4R1-S7';

if (ver =~ "^18\.1R2")
  fixes['18.1R'] = '18.1R2-S4';
else
  fixes['18.1R'] = '18.1R3-S4';

if (ver =~ "^18\.2R1")
  fixes['18.2'] = '18.2R1-S5';
else
  fixes['18.2'] = '18.2R2-S1';

fixes['18.2X75'] = '18.2X75-D40';
fixes['18.3'] = '18.3R1-S3';
fixes['18.4'] = '18.4R1-S1';
fixes['19.1'] = '19.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
