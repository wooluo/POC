#
# 
#

include('compat.inc');

if (description)
{
  script_id(145073);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/20");

  script_cve_id(
    "CVE-2020-25681",
    "CVE-2020-25682",
    "CVE-2020-25683",
    "CVE-2020-25684",
    "CVE-2020-25685",
    "CVE-2020-25686",
    "CVE-2020-25687"
  );

  script_name(english:"dnsmasq < 2.83 Multiple Vulnerabilities (DNSPOOQ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote DNS / DHCP service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of dnsmasq installed on the remote host is prior to 2.83. It is, therefore, affected by multiple
vulnerabilities:

  - Multiple remote buffer overflows in the DNSSEC implementation. (CVE-2020-25681, CVE-2020-25682, CVE-2020-25683,
    CVE-2020-25687)

  - A UDP DNS cache poisoning vulnerability. (CVE-2020-25684)

  - Usage of a known weak hashing function. (CVE-2020-25685)

  - An issue handling multiple simultaneous DNS queries. (CVE-2020-25686)

  Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
  number.");
  script_set_attribute(attribute:"see_also", value:"http://www.thekelleys.org.uk/dnsmasq/CHANGELOG");
  script_set_attribute(attribute:"see_also", value:"https://www.jsof-tech.com/disclosures/dnspooq/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to dnsmasq 2.83 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25681");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:thekelleys:dnsmasq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dns_version.nasl");
  script_require_keys("dns_server/version", "Settings/ParanoidReport");
  script_require_ports("Services/dns", 53);

  exit(0);
}

include('audit.inc');

app_name = 'dnsmasq';
port = get_kb_item('Services/udp/dns');

if (!port)
  port = 53;

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

# dnsmasq replies to BIND.VERSION
version = tolower(get_kb_item_or_exit('dns_server/version'));
display_version = version;

if (version !~ "dnsmasq-(v)?")
  audit(AUDIT_NOT_LISTEN, app_name, port);

version = preg_replace(pattern:"^dnsmasq-(v)?(.*)$", replace:"\2", string:version);

if (version == '2')
  audit(AUDIT_VER_NOT_GRANULAR, app_name, port, display_version);

fix = '2.83';
if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version, 'udp');

report = '\n' +
         '\n  Installed version : ' + display_version +
         '\n  Fixed version     : dnsmasq-' + fix +
         '\n';

security_report_v4(port:port, proto:'udp', severity:SECURITY_HOLE, extra:report);
