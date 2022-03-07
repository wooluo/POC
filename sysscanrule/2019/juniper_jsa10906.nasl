#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121066);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/18 12:05:36");

  script_cve_id("CVE-2019-0006");
  script_xref(name:"JSA", value:"JSA10906");

  script_name(english:"Juniper Junos Packet Forwarding Engine Potential RCE (JSA10906)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a potential remote code execution vulnerability due to
how the Packet Forwarding Engine manager (FXPC) handles HTTP packets.
An attacker could potentially crash the fxpc daemon or execute code.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10906");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in
Juniper advisory JSA10906.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0006");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/10");

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
include("junos_kb_cmd_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

fixes = make_array();

# 14.1X53 versions prior to 14.1X53-D47 on EX and QFX Virtual Chassis Platforms;
# 15.1X53 versions prior to 15.1X53-D50 on EX and QFX Virtual Chassis Platforms.
if (model =~ '^(QFX|EX)')
{
  fixes['14.1X53'] = '14.1X53-D47';
  fixes['15.1X53'] = '15.1X53-D50';
}

# 15.1 versions prior to 15.1R7-S3 all Virtual Chassis Platforms
fixes['15.1R'] = '15.1R7-S3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = FALSE;

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);

