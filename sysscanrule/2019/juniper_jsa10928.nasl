#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125309);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/22 10:34:58");

  script_cve_id("CVE-2019-0039");
  script_bugtraq_id(107899);
  script_xref(name:"JSA", value:"JSA10928");
  script_xref(name:"IAVA", value:"2019-A-0121");

  script_name(english:"Juniper JSA10928");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to
tested version. It is, therefore, affected by a vulnerability as
referenced in the JSA10928 advisory. 

If REST API is enabled, the Junos OS login credentials are vulnerable to
brute force attacks. The high default connection limit of the REST API may
allow an attacker to brute-force passwords using advanced scripting techniques.
Additionally, administrators who do not enforce a strong password policy can
increase the likelihood of success from brute force attacks.

Note that GizaNE has not tested for this issue but has instead relied only on
the application's self-reported version number.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10928
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10928");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0039");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

fixes['14.1X53'] = '14.1X53-D49';
fixes['15.1'] = '15.1F6-S12';
fixes['15.1X49'] = '15.1X49-D160';
fixes['15.1X53'] = '15.1X53-D236';
fixes['16.1'] = '16.1R3-S10';
fixes['16.1X65'] = '16.1X65-D49';
fixes['16.2'] = '16.2R2-S7';
fixes['17.1'] = '17.1R2-S10';
fixes['17.2'] = '17.2R1-S8';
fixes['17.3'] = '17.3R3-S2';
fixes['17.4'] = '17.4R1-S6';
fixes['18.1'] = '18.1R2-S4';
fixes['18.2'] = '18.2R1-S5';
fixes['18.2X75'] = '18.2X75-D30';
fixes['18.3'] = '18.3R1-S1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);


override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration system services rest | display set");

if (buf)
{
  override = FALSE;
  pattern_rest_api_http = '^set system services rest http';
  pattern_rest_explorer = '^set system services rest enable-explorer';

  if (!junos_check_config(buf:buf, pattern:pattern_rest_api_http) &&
      !junos_check_config(buf:buf, pattern:pattern_rest_explorer))
    audit(AUDIT_HOST_NOT, 'vulnerable as it does not appear to have rest api enabled');

  # Rest API enabled but workaround setup
  # set system services rest control connection-limit 100
  pattern_workaround  = 'set system services rest control connection-limit 100';
  if (junos_check_config(buf:buf, pattern:pattern_workaround))
  {
    audit(AUDIT_HOST_NOT, 'vulnerable as control connection-limit 100 is set enabled');
  }
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
