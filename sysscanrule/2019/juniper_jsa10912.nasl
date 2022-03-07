#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");
 
if (description)
{
  script_id(121111);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/26  4:50:08");

  script_cve_id("CVE-2019-0012");
  script_xref(name:"JSA", value:"JSA10912");

  script_name(english:"Junos OS: pd crash on VPLS PE upon receipt of specific BGP message (JSA10912)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability which
allows an attacker to craft a specific BGP message to cause the 
routing protocol daemon (rpd) process to crash and restart. While rpd
restarts after a crash, repeated crashes can result in an extended 
DoS condition.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10912");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10912.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0012");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/11");

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
fixes['12.1X46'] = '12.1X46-D81';
fixes['12.3'] = '12.3R12-S12';
fixes['12.3X48'] = '12.3X48-D76';
fixes['14.1X53'] = '14.1X53-D48';
fixes['15.1F'] = '15.1F6-S12';
fixes['15.1R'] = '15.1R7-S2';
fixes['15.1X49'] = '15.1X49-D150';
fixes['15.1X53'] = '15.1X53-D68';
fixes['16.1'] = '16.1R3-S10';
fixes['16.2'] = '16.2R2-S7';
fixes['17.1'] = '17.1R2-S9';
fixes['17.2'] = '17.2R1-S7';
fixes['17.3'] = '17.3R3-S2';
fixes['17.4'] = '17.4R1-S5';
fixes['18.1'] = '18.1R2-S3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix);
  security_warning(port:0, extra:report);
}
else security_warning(0);
