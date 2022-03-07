#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127107);
  script_version("1.3");
  script_cvs_date("Date: 2019/08/05  9:28:46");

  script_cve_id(
    "CVE-2019-12255",
    "CVE-2019-12256",
    "CVE-2019-12257",
    "CVE-2019-12258",
    "CVE-2019-12259",
    "CVE-2019-12260",
    "CVE-2019-12261",
    "CVE-2019-12262",
    "CVE-2019-12263",
    "CVE-2019-12264",
    "CVE-2019-12265"
  );
  script_xref(name:"IAVA", value:"2019-A-0274");

  script_name(english:"SonicWall SonicOS Firewall Multiple Management Vulnerabilities (URGENT/11)");
  script_summary(english:"Checks the version of SonicOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote SonicWall firewall is running a version of SonicOS that is affected
by multiple vulnerabilities:

  - Stack overflow in the parsing of IPv4 packets IP options. (CVE-2019-12256)

  - TCP Urgent Pointer = 0 leads to integer underflow (CVE-2019-12255)

  - TCP Urgent Pointer state confusion caused by malformed TCP AO option (CVE-2019-12260)

  - TCP Urgent Pointer state confusion during connect to a remote host (CVE-2019-12261)

  - TCP Urgent Pointer state confusion due to race condition (CVE-2019-12263)

  - Heap overflow in DHCP Offer/ACK parsing in ipdhcpc (CVE-2019-12257)

  - TCP connection DoS via malformed TCP options (CVE-2019-12258)

  - Handling of unsolicited Reverse ARP replies (Logical Flaw) (CVE-2019-12262)

  - Logical flaw in IPv4 assignment by the ipdhcpc DHCP client (CVE-2019-12264)

  - DoS via NULL dereference in IGMP parsing (CVE-2019-12259)

  - IGMP Information leak via IGMPv3 specific membership report (CVE-2019-12265)

Note that GizaNE has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2019-0009");
  # https://www.sonicwall.com/support/product-notification/?sol_id=190717234810906
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://armis.com/urgent11/");
  # https://www.windriver.com/security/announcements/tcp-ip-network-stack-ipnet-urgent11/
  script_set_attribute(attribute:"see_also", value:"");
  # https://go.armis.com/hubfs/White-papers/Urgent11%20Technical%20White%20Paper.pdf
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12255");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sonicwall:sonicos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl");
  script_require_keys("Host/OS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

os = get_kb_item_or_exit("Host/OS");
if (os !~ "^SonicOS" ) audit(AUDIT_OS_NOT, "SonicWall SonicOS");

# SonicOS Enhanced 5.9.1.10-1o on a SonicWALL NSA 220
match = pregmatch(pattern:"^SonicOS(?: Enhanced)? ([0-9.]+)(?:-[^ ]*)? on a SonicWALL (.*)$", string:os);
if (isnull(match)) exit(1, "Failed to identify the version of SonicOS.");
version = match[1];
model = match[2];

fix = NULL;

# NSA, TZ, SOHO (GEN5)
if (version =~ "^5\." && (model =~ "^(NSA|TZ|SOHO)") ) {
  if (version =~ "^5\.[0-8]\.")
    fix = NULL; # Patch not required.
  else if (version =~ "^5\.9\.0\.")
    fix = "5.9.0.8";
  else if (version =~ "^5\.9\.1\.")
    fix = "5.9.1.13";
}

# NSA, TZ, SOHO, SuperMassive 92xx/94xx/96xx (GEN6+)
if (version =~ "^6\." && (model =~ "^(NSA|TZ|SOHO|SuperMassive 9[246][0-9][0-9])") ) {
  if (version =~ "^6\.1\.")
    fix = NULL; # Patch not required.
  else if (version =~ "^6\.2\.[0-3]\.")
    fix = "6.2.3.2";
  else if (version =~ "^6\.2\.4\.")
    fix = "6.2.4.4";
  else if (version =~ "^6\.2\.5\.")
    fix = "6.2.5.4";
  else if (version =~ "^6\.2\.6\.")
    fix = "6.2.6.2";
  else if (version =~ "^6\.2\.7\.")
    fix = "6.2.7.5";
  else if (version =~ "^6\.2\.9\.")
    fix = "6.2.9.3";
  else if (version =~ "^6\.5\.0\.")
    fix = "6.5.0.4";
  else if (version =~ "^6\.5\.1\.")
    fix = "6.5.1.5";
  else if (version =~ "^6\.5\.2\.")
    fix = "6.5.2.4";
  else if (version =~ "^6\.5\.3\.")
    fix = "6.5.3.4";
  else if (version =~ "^6\.5\.4\.")
    fix = "6.5.4.4";
}

# SuperMassive 12K, 10K, 9800
if (model =~ "^SuperMassive (1[02]K|9800)") {
  if (version =~ "^6\.0\.")
    fix = NULL; # Patch not required.
  else if (version =~ "^6\.2\.7\.")
    fix = "6.2.7.11";
  else if (version =~ "^6\.4\.1\.")
    fix = "6.4.1.1";
  else if (version =~ "^6\.5\.1\.")
    fix = "6.5.1.10";
}

if (isnull(fix))
  audit(AUDIT_DEVICE_NOT_VULN, "SonicWALL " + model, "SonicOS " + version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = 0;
  report =
    '\n  Device Model              : ' + model +
    '\n  Installed SonicOS version : ' + version +
    '\n  Fixed SonicOS version     : ' + fix +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_DEVICE_NOT_VULN, "SonicWALL " + model, "SonicOS " + version);

