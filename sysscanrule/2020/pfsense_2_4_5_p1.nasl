##
# 
##

include('compat.inc');

if (description)
{
  script_id(146206);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2020-12662", "CVE-2020-12663", "CVE-2020-12762");

  script_name(english:"pfSense 2.4.x < 2.4.5-p1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense install is a version 2.4.x prior to 2.4.5-p1. It is,
therefore, affected by the following vulnerabilities in its subcomponents:

  - Unbound before 1.10.1 has Insufficient Control of Network Message Volume, aka an 'NXNSAttack' issue. This is
    triggered by random subdomains in the NSDNAME in NS records. (CVE-2020-12662)

  - Unbound before 1.10.1 has an infinite loop via malformed DNS answers received from upstream servers.
    (CVE-2020-12663)

  - json-c through 0.14 has an integer overflow and out-of-bounds write via a large JSON file, as demonstrated by
    printbuf_memappend. (CVE-2020-12762)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://docs.netgate.com/pfsense/en/latest/releases/2-4-5-p1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.4.5-p1 or later, or apply patches as noted in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12762");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pfsense:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bsdperimeter:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netgate:pfsense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pfsense_detect.nbin");
  script_require_keys("Host/pfSense");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

if (!get_kb_item('Host/pfSense')) audit(AUDIT_HOST_NOT, 'pfSense');

app_info = vcf::pfsense::get_app_info();
constraints = [
  {'min_version':'2.4.0', 'max_version':'2.4.5', 'fixed_version':'2.4.5-p1'}
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
