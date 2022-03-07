#TRUSTED ac591ec87b4adabebd33bb44325b7347e478ba1d088d2403288637820e92f6ed717b560d6fe89129da3f194dcc640fddaa23ae28bb3135f7165377f1d4c8314c002c990a528381edb06413414033fc9e330a47701bf0ca2c9282d05c7b8963c5bc2e8f7849ab7e6f58017b0bc21ff17859578379a59270e7d535475603ab28dadb0252b60a57c56cf779397bcd6b37ee6473ad127a9c91d2f6c8bae0a115bc4c45a87f4687aaba6fe6d6ca0e29f553f5efb1b933106cc5d5099f3e6c1d6eec28da3b39f6cd834597a07ef87765c080bab4b2df7f56a49929e67be57f6157f08b0e3f59667f7f520845dfb6b93dd89785190d1edf5be7149410660b45e23b311f93d89ae7c7edfa4a81abbb68de07bcfe7367ec31d2cbd5be20889aad02a185c7fff84fc1d403f62b848968e848de6b3cd64f07e5d1689fa3f8a9c54a1ace94c6ce99df53d50cfcf2d89c58af600b8808e215f043fed9641ae6caa38c077592f4fa84fda30cae990a8cb700fbf163505d265f07284baec4799b81b1a01ede450ea6ae2d676c1da021f0c31a64f7d52a347c4b8f50fdc50d07a1d54746a8cc4f0c1cce2995898a1436138cfc842f0f197c55c87799facc1fc77e5bbd3060632bc079ccec4dfdf3a6db7dbed9219e236d5b547c2429f0ca4438aefbb01b83f0341288e3c8ed0ec250b00794011cf4405da97351bf00e71844bce0d80eeff22ec9d7
#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121643);
  script_version("1.3");
  script_cvs_date("Date: 2019/02/22  9:55:50");

  script_cve_id("CVE-2019-0015");
  script_xref(name:"JSA", value:"JSA10915");

  script_name(english:"Junos OS: Deleted dynamic VPN users are allowed to establish VPN connections until reboot (JSA10915)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a vulnerability that allows deleted 
dynamic VPN users to establish dynamic VPN connections until the 
device is rebooted.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10915");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10915.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0015");

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
fixes['12.3X48'] = '12.3X48-D75';
fixes['15.1X49'] = '15.1X49-D150';
fixes['17.3'] = '17.3R3';
fixes['17.4'] = '17.4R2';
fixes['18.1'] = '18.1R3';
fixes['18.2'] = '18.2R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);


# If dynamic vpn isn't enabled in some form, audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  override = FALSE;
  pattern = "^set vpn dyn-vpn";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as it does not appear to have dynamic vpn enabled.');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);

