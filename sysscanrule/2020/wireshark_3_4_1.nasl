##
# 
##


include('compat.inc');

if (description)
{
  script_id(144642);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id(
    "CVE-2020-26418",
    "CVE-2020-26419",
    "CVE-2020-26420",
    "CVE-2020-26421"
  );
  script_xref(name:"IAVB", value:"2021-B-0001");

  script_name(english:"Wireshark 3.4.x < 3.4.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is prior to 3.4.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the wireshark-3.4.1 advisory.

  - Memory leak in Kafka protocol dissector in Wireshark 3.4.0 and 3.2.0 to 3.2.8 allows denial of service via
    packet injection or crafted capture file. (CVE-2020-26418)

  - Crash in USB HID protocol dissector and possibly other dissectors in Wireshark 3.4.0 and 3.2.0 to 3.2.8
    allows denial of service via packet injection or crafted capture file. (CVE-2020-26421)

  - Memory leak in RTPS protocol dissector in Wireshark 3.4.0 and 3.2.0 to 3.2.8 allows denial of service via
    packet injection or crafted capture file. (CVE-2020-26420)

  - Memory leak in the dissection engine in Wireshark 3.4.0 allows denial of service via packet injection or
    crafted capture file. (CVE-2020-26419)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-3.4.1.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2020-16");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2020-17");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2020-18");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2020-19");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 3.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26419");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

constraints = [
  { 'min_version' : '3.4.0', 'fixed_version' : '3.4.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
