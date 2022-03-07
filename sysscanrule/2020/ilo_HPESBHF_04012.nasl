#
# 
#

include('compat.inc');

if (description)
{
  script_id(140770);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/25");

  script_cve_id(
    "CVE-2020-11896",
    "CVE-2020-11898",
    "CVE-2020-11900",
    "CVE-2020-11906",
    "CVE-2020-11907",
    "CVE-2020-11911",
    "CVE-2020-11912",
    "CVE-2020-11914"
  );
  script_xref(name:"HP", value:"HPESBHF04012");

  script_name(english:"HP iLO 3 < 1.93 / HP iLO 4 < 2.75 / HP iLO 5 < 2.18 Ripple20 Multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote HP Integrated Lights-Out server's web interface is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Multiple security vulnerabilities have been identified in Integrated Lights-Out firmware generation 3 (iLO 3) prior
to version 1.93, generation 4 (iLO 4) prior to version 2.75, and generation 5 (iLO 5) prior to version 2.18. The
vulnerabilities could be remotely exploited to execute code, cause denial of service, and expose sensitive information.

Note: These vulnerabilities are collectively named Ripple20. iLO 3, iLO4, and iLO 5 are only exposed to a portion of
the Ripple20 vulnerabilities.");
  # https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=hpesbhf04012en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e67ddae");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP iLO 3 firmware version 1.93 or later, iLO 4 firmware version 2.75 or later, or HP iLO 5 firmware version 2.18 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11896");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out_3_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out_4_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out_5_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ilo_detect.nasl");
  script_require_keys("www/ilo", "ilo/generation", "ilo/firmware");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

version = get_kb_item_or_exit('ilo/firmware');

# Each generation has its own series of firmware version numbers.
generation = get_kb_item_or_exit('ilo/generation');

if (generation !~ "^[345]$") audit(AUDIT_HOST_NOT, "iLO generation 3/4/5");

port = get_http_port(default:80, embedded: TRUE);
app_info = vcf::get_app_info(app:'ilo', port:port, webapp:TRUE);

constraints = [
  { 'generation' : '3', 'fixed_version' : '1.93' },
  { 'generation' : '4', 'fixed_version' : '2.75' },
  { 'generation' : '5', 'fixed_version' : '2.18' }
];
vcf::ilo::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
