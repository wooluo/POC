#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121472);
  script_version("1.1");
  script_cvs_date("Date: 2019/01/30 11:08:44");

  script_cve_id("CVE-2019-6485");

  script_name(english:"Citrix NetScaler Gateway TLS Padding Oracle Vulnerability (CTX240139)");
  script_summary(english:"Checks the Citrix NetScaler version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a padding oracle vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix NetScaler device is affected by a TLS padding oracle
vulnerability. An attacker may be able to leverage this vulnerability
to decrypt TLS traffic. Please refer to advisory CTX240139 for more
information.

Note appliances with all CBC-based ciphers disabled are not affected by
this vulnerability. Additionally, the following models are not
affected:
  - MPX 5900 series
  - MPX/SDX 8900 series
  - MPX/SDX 15000-50G
  - MPX/SDX 26000-50S series
  - MPX/SDX 26000-100G series
  - MPX/SDX 26000 series
  - VPX");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX240139");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix NetScaler Gateway version 10.5 build 69.5 / 11.0
build 72.17  / 11.1 build 60.14 / 12.0 build 60.9 / 12.1 build 50.31
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6485");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:citrix:netscaler_access_gateway_firmware");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Multiple models are not affected and a mitigation strategy is provided
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "Citrix NetScaler";
version = get_kb_item_or_exit("Host/NetScaler/Version");
build = get_kb_item("Host/NetScaler/Build");
enhanced = get_kb_item("Host/NetScaler/Enhanced");
fixed_build = NULL;

if (isnull(build)) exit(0, "The build number of " + app_name + " " + version + " could not be determined.");

display_version = version + "-" + build;
version = version + "." + build;

if (!enhanced)
{
  # non-enhanced builds
  if (version =~ "^10\.5" && ver_compare(ver:build, fix:"69.5") < 0)
  {
    fixed_build = "69.5";
  }
  else if (version =~ "^11\.0" && ver_compare(ver:build, fix:"72.17") < 0)
  {
    fixed_build = "72.17";
  }
  else if (version =~ "^11\.1" && ver_compare(ver:build, fix:"60.14") < 0)
  {
    fixed_build = "60.14";
  }
  else if (version =~ "^12\.0" && ver_compare(ver:build, fix:"60.9") < 0)
  {
    fixed_build = "60.9";
  }
  else if (version =~ "^12\.1" && ver_compare(ver:build, fix:"50.31") < 0)
  {
    fixed_build = "50.31";
  }
}

if (isnull(fixed_build))
{
  audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
}

report =
   '\n  Installed version : ' + display_version +
   '\n  Installed build   : ' + build +
   '\n  Fixed build       : ' + fixed_build +
   '\n';

security_report_v4(port:0, severity:SECURITY_WARNING, extra:report, xss: TRUE);
