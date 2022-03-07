#TRUSTED 5343d2763badde945385d54fcbb124c441d296436ac037b651961acecb0458bce0995371ff7f4564316fe2edb8fa74a90f5283de8a85deb9e25878287c4725e112b9c1d91707b0accc4833aa54ed55d6c29f23fc679b58d20a17a7fc693e0bd76033debd95d37322046407d33f452012fb1a55265097f26c0a24ea79422a286b692292e72933fc4dc57fd737cc50c804ec3e04ec1ee8bdcd590692eb3e4720032a0e85441d606b1139983d7d43d0cc93b3b96703cd385a1373e376b96f9bd23a2741254b9557df88e67727bfb459f435887452598d8b8ae4fd023f626889ad380c6db41d2ba859d5b2234b728a335b0c85cb1fb6cbfc71913e512b34acaed8be489d107e2ccb831ef23157af7a09fb139a5dcaf94830bf256247d5043e59bbdb7334c444a87bb6fed380ecd111af6a131e5a65499026018aef39f310c74be5239ab3cb1aa627f2630da00847bfed8910e093e3841215321868a2858d6095edeeab2b26b9d9c3f65c90ea7dad3a4a76dc838ee91ea4ef4d816ac0a6a52d832672612724ba48d45a67cff3a5ad9127d7e3cc9f31808582b2299101828c9a61ebe7bb8d06d08295f68b79879d952352feb84e08b524dd2f380cf50c7e762abfb0af5d7e8d3f7651b43d37aa42740e76c3aa032a1614250e8634fdafe51e1c6999851eaf16cc5c46cdc1686877afee36b72ddb2e4e8a39d9d8885c4e669100c1538d
#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121644);
  script_version("1.3");
  script_cvs_date("Date: 2019/02/22  9:55:50");

  script_cve_id("CVE-2019-0010");
  script_xref(name:"JSA", value:"JSA10910");

  script_name(english:"Junos OS: Crafted HTTP traffic may cause UTM to consume all mbufs, leading to Denial of Service (JSA10910)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability. An 
SRX Series Service Gateway configured for Unified Threat Management 
(UTM) may experience a denial of service due to the receipt of 
crafted HTTP traffic.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10910");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10910.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0010");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/07");

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
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
if ( 'SRX' >!< model)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['12.1X46'] = '12.1X46-D81';
fixes['12.3X48'] = '12.3X48-D77';
fixes['15.1X49'] = '15.1X49-D101';


fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If  Unified Threat Management (UTM) isn't enabled in some form, audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  override = FALSE;
  pattern = "^set security utm";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as it does not appear to have UTM enabled.');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);

