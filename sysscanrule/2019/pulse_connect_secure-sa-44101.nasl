#
# (c) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124766);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/13 17:57:55");

  script_cve_id(
    "CVE-2019-11510",
    "CVE-2019-11508",
    "CVE-2019-11540",
    "CVE-2019-11543",
    "CVE-2019-11541",
    "CVE-2019-11542",
    "CVE-2019-11539",
    "CVE-2019-11538",
    "CVE-2019-11509",
    "CVE-2019-11507",
    "CVE-2018-16513",
    "CVE-2018-18284",
    "CVE-2018-15911",
    "CVE-2018-15910",
    "CVE-2018-15909"
  );
  script_bugtraq_id(
     108073,
     107451,
     105122
  );
  script_xref(name:"IAVB", value:"2019-B-0049");

  script_name(english:"Pulse Connect Secure Multiple Vulnerabilities (SA44101)");
  script_summary(english:"Checks PCS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Pulse Connect
Secure running on the remote host is affected by multiple
vulnerabilities.

   - An arbitrary file read vulnerability exists in PCS. An
     unauthenticated, remote attacker can exploit this, via specially
     crafted URI, to read arbitrary files and disclose sensitive
     information. (CVE-2019-11510)

   - Multiple vulnerabilities are found in Ghostscript.(CVE-2018-16513
     , CVE-2018-18284, CVE-2018-15911, CVE-2018-15910, CVE-2018-15909)

   - A session hijacking vulnerability exists in PCS. An
     unauthenticated, remote attacker can exploit this, to perform
     actions in the user or administrator interface with the
     privileges of another user. (CVE-2019-11540)

   - An authentication leaks seen in users using SAML authentication
     with the reuse existing NC (Pulse) session option.
     (CVE-2019-11541)

   - Multiple vulnerabilities found in the admin web interface of PCS.
     (CVE-2019-11543, CVE-2019-11542, CVE-2019-11509, CVE-2019-11539)

   - Multiple vulnerabilities found in Network File Share (NFS) of PCS
     , allows the attacker to read/write arbitrary files on the
     affected device. (CVE-2019-11538, CVE-2019-11508)

   - A cross-site scripting (XSS) vulnerability exists in application
     launcher page due to improper validation of user-supplied input
     before returning it to users. An attacker can exploit this, by
     convincing a user to click a specially crafted URL, to execute
     arbitrary script code in a user's browser session.
     (CVE-2019-11507)

Refer to the vendor advisory for additional information.");
  # https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate version referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11540");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulse_secure:pulse_connect_secure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Misc.");

  script_dependencies("pulse_connect_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Connect Secure");

  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:'Pulse Connect Secure', port:443);

constraints = [
  {'min_version' : '8.3R1' , 'fixed_version' : '8.3R7.1'},
  {'min_version' : '8.2R1' , 'fixed_version' : '8.2R12.1'},
  {'min_version' : '8.1R1' , 'fixed_version' : '8.1R15.1'},
  {'min_version' : '9.0R1' , 'fixed_version' : '9.0R3.4', 'display_version' : '9.0R3.4 / 9.0R4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
