#
# (C) WebRAY Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121642);
  script_version("1.2");
  script_cvs_date("Date: 2019/03/27 13:17:50");

  script_cve_id("CVE-2019-0001");
  script_bugtraq_id(106541);
  script_xref(name:"JSA", value:"JSA10900");

  script_name(english:"Juniper Junos MX Malformed Packet - DOS (JSA10900)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
  "Receipt of a malformed packet on MX Series devices with dynamic 
  vlan configuration can trigger an uncontrolled recursion loop in 
  the Broadband Edge subscriber management daemon (bbe-smgd), 
  and lead to high CPU usage and a crash of the bbe-smgd service. 
  Repeated receipt of the same packet can result in an extended denial of service condition for the device.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10900");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in
Juniper advisory JSA10900.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0001");


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

include('audit.inc');
include('junos.inc');
include("junos_kb_cmd_func.inc");
include('misc_func.inc');

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
check_model(model:model, flags:MX_SERIES, exit_on_fail:TRUE);

fixes = make_array();
fixes['16.1'] = '16.1R7-S1';
fixes['16.2'] = '16.2R2-S7';
fixes['17.1'] = '17.1R2-S10';
fixes['17.2'] = '17.2R3';
fixes['17.3'] = '17.3R3-S1';
fixes['17.4'] = '17.4R2';
fixes['18.1'] = '18.1R3';
fixes['18.2'] = '18.2R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If  dynamic vlan isn't enabled in some form, audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  override = FALSE;
  pattern = "^set dynamic-profile";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as it does not appear to have dynamic vlan enabled.');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);

