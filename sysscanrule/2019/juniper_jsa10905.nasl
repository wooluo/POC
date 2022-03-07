#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122241);
  script_version("1.1");
  script_cvs_date("Date: 2019/02/15 11:32:52");

  script_cve_id("CVE-2019-0005");
  script_xref(name:"JSA", value:"JSA10905");

  script_name(english:"Junos OS: Stateless firewall filter ignores IPv6 extension headers (JSA10905)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a vulnerability which may allow IPv6 
packets that should have been blocked to be forwarded.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10905");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10905.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0005");

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


if (!(  model =~ '^EX2300' || model =~ '^EX3400' || model == 'EX4600' || model =~ '^QFX3K' || model =~ '^QFX5200' || model =~ '^QFX5110'
  || model =~ '^QFX5K'))
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();

fixes['14.1X53'] = '14.1X53-D47';
fixes['15.1R'] = '15.1R7';

if (model == 'QFX5200' || model == 'QFX5110')
{
    fixes['15.1X53'] = '15.1X53-D234';
}
else if (model == 'EX2300' || model == 'EX3400')
{
    fixes['15.1X53'] = '15.1X53-D591';
}
fixes['16.1'] = '16.1R7';
fixes['17.1'] = '17.1R2-S10';
fixes['17.2'] = '17.2R3';
fixes['17.3'] = '17.3R3';
fixes['17.4'] = '17.4R2';
fixes['18.1'] = '18.1R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
