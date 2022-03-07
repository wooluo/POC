#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124238);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/23 16:17:57");

  script_cve_id("CVE-2019-0028");
  script_xref(name:"IAVA", value:"2019-A-0121");

  script_name(english:"Juniper JSA10932");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to
tested version. It is, therefore, affected by a vulnerability On Junos 
devices with the BGP graceful restart helper mode enabled or the BGP 
graceful restart mechanism enabled. A remote attacker can exploit this
by simulating a specific BGP session restart to cause a denial of
service as referenced in the JSA10932 advisory. Note that GizaNE has 
not tested for this issue but has instead relied only on the 
application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10932");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10932");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0028");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
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

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

fixes["16.1"] = "16.1R7";
fixes["16.1X65"] = "16.1X65-D48";
fixes["16.2"] = "16.2R2-S8";
fixes["17.1"] = "17.1R2-S7";
fixes["17.2"] = "17.2R1-S7";
fixes["17.2X75"] = "17.2X75-D102";
fixes["17.3"] = "17.3R2-S2";
fixes["17.4"] = "17.4R1-S4";
fixes["18.1"] = "18.1R2";

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
