##
# 
##

include('compat.inc');

if (description)
{
  script_id(144949);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2020-1971", "CVE-2020-8265", "CVE-2020-8287");

  script_name(english:"Node.js 10.x < 10.23.1 / 12.x < 12.20.1 / 14.x < 14.15.4 / 15.x < 15.5.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is 10.x prior to 10.23.1, 12.x prior to 12.20.1, 14.x prior to
14.15.4, or 15.x prior to 15.5.1. It is, therefore, affected by multiple vulnerabilities as referenced in the
january-2021-security-releases advisory.

  - The X.509 GeneralName type is a generic type for representing different types of names. One of those name
    types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different
    instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both
    GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a
    possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 1)
    Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in
    an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp
    authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an
    attacker can control both items being compared then that attacker could trigger a crash. For example if
    the attacker can trick a client or server into checking a malicious certificate against a malicious CRL
    then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a
    certificate. This checking happens prior to the signatures on the certificate and CRL being verified.
    OpenSSL's s_server, s_client and verify tools have support for the -crl_download option which implements
    automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an
    unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of
    EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will
    accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue.
    Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected
    1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w). (CVE-2020-1971)

  - Node.js versions before 10.23.1, 12.20.1, 14.15.4, 15.5.1 allow two copies of a header field in an HTTP
    request (for example, two Transfer-Encoding header fields). In this case, Node.js identifies the first
    header field and ignores the second. This can lead to HTTP Request Smuggling. (CVE-2020-8287)

  - Node.js versions before 10.23.1, 12.20.1, 14.15.4, 15.5.1 are vulnerable to a use-after-free bug in its TLS
    implementation. When writing to a TLS enabled socket, node::StreamBase::Write calls node::TLSWrap::DoWrite
    with a freshly allocated WriteWrap object as first argument. If the DoWrite method does not return an
    error, this object is passed back to the caller as part of a StreamWriteResult structure. This may be
    exploited to corrupt memory leading to a Denial of Service or potentially other exploits. (CVE-2020-8265)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://nodejs.org/en/blog/vulnerability/january-2021-security-releases/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c59c0b90");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 10.23.1 / 12.20.1 / 14.15.4 / 15.5.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8265");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_nodejs_installed.nbin", "nodejs_win_installed.nbin");
  script_require_ports("installed_sw/Node.js");

  exit(0);
}

include('vcf.inc');

win_local = FALSE;
if (get_kb_item('SMB/Registry/Enumerated')) win_local = TRUE;

app_info = vcf::get_app_info(app:'Node.js', win_local:win_local);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '10.0.0', 'fixed_version' : '10.23.1' },
  { 'min_version' : '12.0.0', 'fixed_version' : '12.20.1' },
  { 'min_version' : '14.0.0', 'fixed_version' : '14.15.4' },
  { 'min_version' : '15.0.0', 'fixed_version' : '15.5.1' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
