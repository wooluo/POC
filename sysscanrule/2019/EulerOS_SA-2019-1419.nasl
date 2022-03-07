#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124922);
  script_version("1.4");
  script_cvs_date("Date: 2019/06/27 13:33:25");

  script_cve_id(
    "CVE-2013-4352",
    "CVE-2013-5704",
    "CVE-2013-6438",
    "CVE-2014-0098",
    "CVE-2014-0117",
    "CVE-2014-0118",
    "CVE-2014-0226",
    "CVE-2014-0231",
    "CVE-2014-3581",
    "CVE-2015-3183",
    "CVE-2015-3185",
    "CVE-2016-0736",
    "CVE-2016-2161",
    "CVE-2016-5387",
    "CVE-2016-8743",
    "CVE-2017-15710",
    "CVE-2017-3167",
    "CVE-2017-3169",
    "CVE-2017-7668",
    "CVE-2017-7679",
    "CVE-2017-9788",
    "CVE-2017-9798",
    "CVE-2018-1303",
    "CVE-2018-1312",
    "CVE-2019-0217"
  );
  script_bugtraq_id(
    66303,
    66550,
    68678,
    68740,
    68742,
    68745,
    68863,
    69248,
    71656,
    75963,
    75965
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : httpd (EulerOS-SA-2019-1419)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the httpd packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - The log_cookie function in mod_log_config.c in the
    mod_log_config module in the Apache HTTP Server before
    2.4.8 allows remote attackers to cause a denial of
    service (segmentation fault and daemon crash) via a
    crafted cookie that is not properly handled during
    truncation.(CVE-2014-0098)

  - A race condition flaw, leading to heap-based buffer
    overflows, was found in the mod_status httpd module. A
    remote attacker able to access a status page served by
    mod_status on a server using a threaded
    Multi-Processing Module (MPM) could send a specially
    crafted request that would cause the httpd child
    process to crash or, possibly, allow the attacker to
    execute arbitrary code with the privileges of the
    'apache' user.(CVE-2014-0226)

  - It was discovered that the HTTP parser in httpd
    incorrectly allowed certain characters not permitted by
    the HTTP protocol specification to appear unencoded in
    HTTP request headers. If httpd was used in conjunction
    with a proxy or backend server that interpreted those
    characters differently, a remote attacker could
    possibly use this flaw to inject data into HTTP
    responses, resulting in proxy cache
    poisoning.(CVE-2016-8743)

  - A NULL pointer dereference flaw was found in the way
    the mod_cache httpd module handled Content-Type
    headers. A malicious HTTP server could cause the httpd
    child process to crash when the Apache HTTP server was
    configured to proxy to a server with caching
    enabled.(CVE-2014-3581)

  - Multiple flaws were found in the way httpd parsed HTTP
    requests and responses using chunked transfer encoding.
    A remote attacker could use these flaws to create a
    specially crafted request, which httpd would decode
    differently from an HTTP proxy software in front of it,
    possibly leading to HTTP request smuggling
    attacks.(CVE-2015-3183)

  - In Apache httpd 2.0.23 to 2.0.65, 2.2.0 to 2.2.34, and
    2.4.0 to 2.4.29, mod_authnz_ldap, if configured with
    AuthLDAPCharsetConfig, uses the Accept-Language header
    value to lookup the right charset encoding when
    verifying the user's credentials. If the header value
    is not present in the charset conversion table, a
    fallback mechanism is used to truncate it to a two
    characters value to allow a quick retry (for example,
    'en-US' is truncated to 'en'). A header value of less
    than two characters forces an out of bound write of one
    NUL byte to a memory location that is not part of the
    string. In the worst case, quite unlikely, the process
    would crash which could be used as a Denial of Service
    attack. In the more likely case, this memory is already
    reserved for future use and the issue has no effect at
    all.(CVE-2017-15710)

  - A NULL pointer dereference flaw was found in the
    httpd's mod_ssl module. A remote attacker could use
    this flaw to cause an httpd child process to crash if
    another module used by httpd called a certain API
    function during the processing of an HTTPS
    request.(CVE-2017-3169)

  - It was discovered that httpd used the value of the
    Proxy header from HTTP requests to initialize the
    HTTP_PROXY environment variable for CGI scripts, which
    in turn was incorrectly used by certain HTTP client
    implementations to configure the proxy for outgoing
    HTTP requests. A remote attacker could possibly use
    this flaw to redirect HTTP requests performed by a CGI
    script to an attacker-controlled proxy via a malicious
    HTTP request.(CVE-2016-5387)

  - A buffer over-read flaw was found in the httpd's
    mod_mime module. A user permitted to modify httpd's
    MIME configuration could use this flaw to cause httpd
    child process to crash.(CVE-2017-7679)

  - A specially crafted HTTP request header could have
    crashed the Apache HTTP Server prior to version 2.4.30
    due to an out of bound read while preparing data to be
    cached in shared memory. It could be used as a Denial
    of Service attack against users of mod_cache_socache.
    The vulnerability is considered as low risk since
    mod_cache_socache is not widely used, mod_cache_disk is
    not concerned by this vulnerability.(CVE-2018-1303)

  - It was discovered that the httpd's mod_auth_digest
    module did not properly initialize memory before using
    it when processing certain headers related to digest
    authentication. A remote attacker could possibly use
    this flaw to disclose potentially sensitive information
    or cause httpd child process to crash by sending
    specially crafted requests to a server.(CVE-2017-9788)

  - A flaw was found in the way httpd handled HTTP Trailer
    headers when processing requests using chunked
    encoding. A malicious client could use Trailer headers
    to set additional HTTP headers after header processing
    was performed by other modules. This could, for
    example, lead to a bypass of header restrictions
    defined with mod_headers.(CVE-2013-5704)

  - A buffer over-read flaw was found in the httpd's
    ap_find_token() function. A remote attacker could use
    this flaw to cause httpd child process to crash via a
    specially crafted HTTP request.(CVE-2017-7668)

  - A race condition was found in mod_auth_digest when the
    web server was running in a threaded MPM configuration.
    It could allow a user with valid credentials to
    authenticate using another username, bypassing
    configured access control restrictions.(CVE-2019-0217)

  - A NULL pointer dereference flaw was found in the
    mod_cache httpd module. A malicious HTTP server could
    cause the httpd child process to crash when the Apache
    HTTP Server was used as a forward proxy with caching.
    (CVE-2013-4352)

  - he dav_xml_get_cdata function in main/util.c in the
    mod_dav module in the Apache HTTP Server before 2.4.8
    does not properly remove whitespace characters from
    CDATA sections, which allows remote attackers to cause
    a denial of service (daemon crash) via a crafted DAV
    WRITE request. (CVE-2013-6438)

  - A denial of service flaw was found in the mod_proxy
    httpd module. A remote attacker could send a specially
    crafted request to a server configured as a reverse
    proxy using a threaded Multi-Processing Modules (MPM)
    that would cause the httpd child process to crash.
    (CVE-2014-0117)

  - A denial of service flaw was found in the way httpd's
    mod_deflate module handled request body decompression
    (configured via the 'DEFLATE' input filter). A remote
    attacker able to send a request whose body would be
    decompressed could use this flaw to consume an
    excessive amount of system memory and CPU on the target
    system.(CVE-2014-0118)

  - A denial of service flaw was found in the way httpd's
    mod_cgid module executed CGI scripts that did not read
    data from the standard input. A remote attacker could
    submit a specially crafted request that would cause the
    httpd child process to hang
    indefinitely.(CVE-2014-0231)

  - It was discovered that in httpd 2.4, the internal API
    function ap_some_auth_required() could incorrectly
    indicate that a request was authenticated even when no
    authentication was used. An httpd module using this API
    function could consequently allow access that should
    have been denied. (CVE-2015-3185)

  - It was discovered that the mod_session_crypto module of
    httpd did not use any mechanisms to verify integrity of
    the encrypted session data stored in the user's
    browser. A remote attacker could use this flaw to
    decrypt and modify session data using a padding oracle
    attack. (CVE-2016-0736)

  - It was discovered that the mod_auth_digest module of
    httpd did not properly check for memory allocation
    failures. A remote attacker could use this flaw to
    cause httpd child processes to repeatedly crash if the
    server used HTTP digest authentication.(CVE-2016-2161)

  - It was discovered that the use of httpd's
    ap_get_basic_auth_pw() API function outside of the
    authentication phase could lead to authentication
    bypass. A remote attacker could possibly use this flaw
    to bypass required authentication if the API was used
    incorrectly by one of the modules used by
    httpd.(CVE-2017-3167)

  - A use-after-free flaw was found in the way httpd
    handled invalid and previously unregistered HTTP
    methods specified in the Limit directive used in an
    .htaccess file. A remote attacker could possibly use
    this flaw to disclose portions of the server memory, or
    cause httpd child process to crash. (CVE-2017-9798)

  - In Apache httpd 2.2.0 to 2.4.29, when generating an
    HTTP Digest authentication challenge, the nonce sent to
    prevent reply attacks was not correctly generated using
    a pseudo-random seed. In a cluster of servers using a
    common Digest authentication configuration, HTTP
    requests could be replayed across servers by an
    attacker without detection. (CVE-2018-1312)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1419
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected httpd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["httpd-2.4.6-80.1.h6",
        "httpd-tools-2.4.6-80.1.h6",
        "mod_ssl-2.4.6-80.1.h6"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd");
}
