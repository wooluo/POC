#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122242);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/18 12:05:36");

  script_cve_id("CVE-2019-0003");
  script_xref(name:"JSA", value:"JSA10902");

  script_name(english:"Junos OS: Multiple vulnerabilities in libxml2 (JSA10902)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a vulnerability. When a specific BGP 
flowspec configuration is enabled and upon receipt of a specific 
matching BGP packet meeting a specific term in the flowspec 
configuration, a reachable assertion failure occurs, causing the 
routing protocol daemon (rpd) process to crash with a core file being
generated.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10902");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10902.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4448");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/15");

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

fixes['12.3R'] = '12.3R12-S10';

if (model =~ '^SRX')
{
    fixes['12.1X46'] = '12.1X46-D77';
    fixes['12.3X48'] = '12.3X48-D70';
    fixes['15.1X49'] = '15.1X49-D140';
}

if (model == 'EX2200/VC' || model == 'EX3200' || model == 'EX3300/VC' || model == 'EX4200' || model == 'EX4300' || 
    model == 'EX4550/VC' || model == 'EX4600' || model == 'EX6200' || model == 'EX8200/VC (XRE)' || model == 'QFX3500'
    || model == 'QFX3600'|| model == 'QFX510')
{
    fixes['14.1X53'] = '14.1X53-D47';
}
if (model == 'EX2300' || model == 'EX3400')
{
    fixes['15.1X53'] = '15.1X53-D59';
}
fixes['15.1R'] = '15.1R3';
fixes['15.1F'] = '15.1F3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
