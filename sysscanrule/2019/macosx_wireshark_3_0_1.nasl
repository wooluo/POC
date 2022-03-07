#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124163);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/30 16:25:06");

  script_cve_id(
    "CVE-2019-10894",
    "CVE-2019-10895",
    "CVE-2019-10896",
    "CVE-2019-10897",
    "CVE-2019-10898",
    "CVE-2019-10899",
    "CVE-2019-10900",
    "CVE-2019-10901",
    "CVE-2019-10902",
    "CVE-2019-10903"
  );
  script_bugtraq_id(
    107834,
    107836
  );

  script_name(english:"Wireshark 3.0.x < 3.0.1 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS / Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote macOS / Mac OS X host
is 3.0.x prior to 3.0.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the wireshark-3.0.1 advisory:

  - The NetScaler file parser could crash. It may be
    possible to make Wireshark crash by injecting a
    malformed packet onto the wire or by convincing someone
    to read a malformed packet trace file. (CVE-2019-10895)

  - The SRVLOC dissector could crash. It may be possible to
    make Wireshark crash by injecting a malformed packet
    onto the wire or by convincing someone to read a
    malformed packet trace file. (CVE-2019-10899)

  - The IEEE 802.11 dissector could go into an infinite
    loop. It may be possible to make Wireshark consume
    excessive CPU resources by injecting a malformed packet
    onto the wire or by convincing someone to read a
    malformed packet trace file. (CVE-2019-10897)

  - The GSUP dissector could go into an infinite loop. It
    may be possible to make Wireshark consume excessive CPU
    resources by injecting a malformed packet onto the wire
    or by convincing someone to read a malformed packet
    trace file. (CVE-2019-10898)

  - The Rbm dissector could go into an infinite loop. It may
    be possible to make Wireshark consume excessive CPU
    resources by injecting a malformed packet onto the wire
    or by convincing someone to read a malformed packet
    trace file. (CVE-2019-10900)

  - The GSS-API dissector could crash. It may be possible to
    make Wireshark crash by injecting a malformed packet
    onto the wire or by convincing someone to read a
    malformed packet trace file. (CVE-2019-10894)

  - The DOF dissector could crash. It may be possible to
    make Wireshark crash by injecting a malformed packet
    onto the wire or by convincing someone to read a
    malformed packet trace file. (CVE-2019-10896)

  - The TSDNS dissector could crash. It may be possible to
    make Wireshark crash by injecting a malformed packet
    onto the wire or by convincing someone to read a
    malformed packet trace file. (CVE-2019-10902)

  - The LDSS dissector could crash. It may be possible to
    make Wireshark crash by injecting a malformed packet
    onto the wire or by convincing someone to read a
    malformed packet trace file. (CVE-2019-10901)

  - The DCERPC SPOOLSS dissector could crash. It may be
    possible to make Wireshark crash by injecting a
    malformed packet onto the wire or by convincing someone
    to read a malformed packet trace file. (CVE-2019-10903)

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-3.0.1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 3.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10894");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_wireshark_installed.nbin");
  script_require_keys("installed_sw/Wireshark", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"Wireshark");

constraints = [
  { "min_version" : "3.0.0", "fixed_version" : "3.0.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
