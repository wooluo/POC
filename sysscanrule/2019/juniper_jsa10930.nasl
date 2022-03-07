#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124327);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/26 11:17:20");

  script_cve_id("CVE-2019-0008");
  script_xref(name:"IAVA", value:"2019-A-0121");

  script_name(english:"Juniper JSA10930");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to
tested version. It is, therefore, affected by a stack based overflow 
vulnerability in the Junos OS Packet Forwarding Engine manager (FXPC)
process on QFX5000 series. A remote attacker can exploit it which can
lead to a remote code execution  as referenced in the JSA10930 advisory.
Note that GizaNE has not tested for this issue but has instead relied only
 on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10930");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10930");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0008");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");

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
fixes = make_array();

model = get_kb_item_or_exit('Host/Juniper/model');

#QFX5000 Series which means QFX5000, QFX5100, QFX5200 and so on. Checking QFX5 for all of them
if ( 'QFX5' >!< model && 'EX4300' >!< model && 'EX4600' >!< model)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes["14.1X53"] = "14.1X53-D51";
fixes["15.1X53"] = "15.1X53-D235";
fixes["17.1"] = "17.1R3";
fixes["17.2"] = "17.2R3";
fixes["17.3"] = "17.3R3-S2";
fixes["17.4"] = "17.4R2-S1";
fixes["18.1"] = "18.1R3-S1";
fixes["18.2"] = "18.2R2";
fixes["18.2X75"] = "18.2X75-D30";
fixes["18.3"] = "18.3R2";

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
