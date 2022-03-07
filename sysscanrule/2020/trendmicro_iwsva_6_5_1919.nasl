##
# 
##

include('compat.inc');

if (description)
{
  script_id(144585);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/24");

  script_cve_id(
    "CVE-2020-8461",
    "CVE-2020-8462",
    "CVE-2020-8463",
    "CVE-2020-8464",
    "CVE-2020-8465",
    "CVE-2020-8466",
    "CVE-2020-27010"
  );

  script_name(english:"Trend Micro IWSVA 6.5 < 6.5 Build 1919 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Trend Micro InterScan Web Security Virtual Appliance (IWSVA) installed on the remote host is 6.5 
prior to 6.5 Build 1919. It is, therefore, affected by multiple vulnerabilities: 

  - Multiple cross-site scripting (XSS) vulnerabilities exist in the web interface of IWSVA due to improper 
  validation of user-supplied input before returning it to users. An unauthenticated, remote attacker can 
  exploit these, by convincing a user to click a specially crafted URL, to execute arbitrary script code 
  in a user's browser session. (CVE-2020-8462, CVE-2020-27010)

  - An authentication bypass vulnerability exists in IWSVA due to insufficient request validation. An 
  unauthenticated, remote attacker can exploit this, by sending specially crafted requests, to bypass 
  authentication and execute arbitrary actions with increased privileges. (CVE-2020-8463)

  - Multiple remote code execution vulnerabilities exist in IWSVA. An unauthenticated, remote attacker 
  can exploit these to bypass authentication and execute arbitrary commands. (CVE-2020-8465, CVE-2020-8466)
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/solution/000283077");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Trend Micro IWSVA version 6.5 Build 1919 or later. Alternatively, apply the mitigating factors outlined
  in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8465");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trendmicro:interscan_web_security_virtual_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_iwsva_version.nbin");
  script_require_keys("Host/TrendMicro/IWSVA/version", "Host/TrendMicro/IWSVA/build");

  exit(0);
}

version  = get_kb_item_or_exit('Host/TrendMicro/IWSVA/version');
build = get_kb_item_or_exit('Host/TrendMicro/IWSVA/build');

name = 'Trend Micro InterScan Web Security Virtual Appliance';

# Only 6.5 affected
if (version !~ "^6\.5($|[^0-9])")
  audit(AUDIT_INST_VER_NOT_VULN, name, version, build);

fix = '1919';

if (ver_compare(ver:build, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, name, version, build);

order = make_list('Installed version', 'Fixed version');
report = make_array(
  order[0], version + ' Build ' + build,
  order[1], '6.5 Build ' + fix
);

report = report_items_str(report_items:report, ordered_fields:order);

security_report_v4(
  port:0,
  severity:SECURITY_HOLE,
  extra:report,
  xss:TRUE,
  xsrf:TRUE
);
