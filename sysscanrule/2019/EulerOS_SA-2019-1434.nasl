#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124937);
  script_version("1.4");
  script_cvs_date("Date: 2019/06/27 13:33:25");

  script_cve_id(
    "CVE-2013-1752",
    "CVE-2013-4238",
    "CVE-2014-4616",
    "CVE-2014-7185",
    "CVE-2014-9365",
    "CVE-2016-0772",
    "CVE-2016-2183",
    "CVE-2016-5636",
    "CVE-2016-5699",
    "CVE-2017-1000158",
    "CVE-2018-1060",
    "CVE-2018-1061",
    "CVE-2018-14647",
    "CVE-2019-5010",
    "CVE-2019-9636",
    "CVE-2019-9948"
  );
  script_bugtraq_id(
    61738,
    63804,
    68119,
    70089,
    71639
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : python (EulerOS-SA-2019-1434)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the python packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - It was found that Python's smtplib library did not
    return an exception when StartTLS failed to be
    established in the SMTP.starttls() function. A man in
    the middle attacker could strip out the STARTTLS
    command without generating an exception on the Python
    SMTP client application, preventing the establishment
    of the TLS layer.(CVE-2016-0772)

  - A vulnerability was discovered in Python, in the
    built-in zipimporter. A specially crafted zip file
    placed in a module path such that it would be loaded by
    a later 'import' statement could cause a heap overflow,
    leading to arbitrary code execution.(CVE-2016-5636)

  - A flaw was found in the way the DES/3DES cipher was
    used as part of the TLS/SSL protocol. A
    man-in-the-middle attacker could use this flaw to
    recover some plaintext data by capturing large amounts
    of encrypted traffic between TLS/SSL server and client
    if the communication used a DES/3DES based
    ciphersuite.(CVE-2016-2183)

  - The Python standard library HTTP client modules (such
    as httplib or urllib) did not perform verification of
    TLS/SSL certificates when connecting to HTTPS servers.
    A man-in-the-middle attacker could use this flaw to
    hijack connections and eavesdrop or modify transferred
    data.(CVE-2014-9365)

  - An integer overflow flaw was found in the way the
    buffer() function handled its offset and size
    arguments. An attacker able to control those arguments
    could use this flaw to disclose portions of the
    application memory or cause it to crash.(CVE-2014-7185)

  - A flaw was found in the way catastrophic backtracking
    was implemented in python's pop3lib's apop() method. An
    attacker could use this flaw to cause denial of
    service.(CVE-2018-1060)

  - The ssl.match_hostname function in the SSL module in
    Python 2.6 through 3.4 does not properly handle a '\\0'
    character in a domain name in the Subject Alternative
    Name field of an X.509 certificate, which allows
    man-in-the-middle attackers to spoof arbitrary SSL
    servers via a crafted certificate issued by a
    legitimate Certification Authority, a related issue to
    CVE-2009-2408.(CVE-2013-4238)

  - It was found that the Python's httplib library (used by
    urllib, urllib2 and others) did not properly check
    HTTPConnection.putheader() function arguments. An
    attacker could use this flaw to inject additional
    headers in a Python application that allowed user
    provided header names or values.(CVE-2016-5699)

  - CPython (aka Python) up to 2.7.13 is vulnerable to an
    integer overflow in the PyString_DecodeEscape function
    in stringobject.c, resulting in heap-based buffer
    overflow (and possible arbitrary code
    execution)(CVE-2017-1000158)

  - A flaw was found in the way catastrophic backtracking
    was implemented in python's difflib.IS_LINE_JUNK
    method. An attacker could use this flaw to cause denial
    of service.(CVE-2018-1061)

  - It was discovered that multiple Python standard library
    modules implementing network protocols (such as httplib
    or smtplib) failed to restrict sizes of server
    responses. A malicious server could cause a client
    using one of the affected modules to consume an
    excessive amount of memory.(CVE-2013-1752)

  - A flaw was found in the way the json module handled
    negative index argument passed to certain functions
    (such as raw_decode()). An attacker able to control
    index value passed to one of the affected functions
    could possibly use this flaw to disclose portions of
    the application memory.(CVE-2014-4616)

  - urllib in Python 2.x through 2.7.16 supports the
    local_file: scheme, which makes it easier for remote
    attackers to bypass protection mechanisms that
    blacklist file: URIs, as demonstrated by triggering a
    urllib.urlopen('local_file:///etc/passwd')
    call.(CVE-2019-9948)

  - Python's elementtree C accelerator failed to initialise
    Expat's hash salt during initialization. This could
    make it easy to conduct denial of service attacks
    against Expat by contructing an XML document that would
    cause pathological hash collisions in Expat's internal
    data structures, consuming large amounts CPU and
    RAM.(CVE-2018-14647)

  - A null pointer dereference vulnerability was found in
    the certificate parsing code in Python. This causes a
    denial of service to applications when parsing
    specially crafted certificates. This vulnerability is
    unlikely to be triggered if application enables SSL/TLS
    certificate validation and accepts certificates only
    from trusted root certificate
    authorities.(CVE-2019-5010)

  - Python 2.7.x through 2.7.16 and 3.x through 3.7.2 is
    affected by: Improper Handling of Unicode Encoding
    (with an incorrect netloc) during NFKC normalization.
    The impact is: Information disclosure (credentials,
    cookies, etc. that are cached against a given
    hostname). The components are: urllib.parse.urlsplit,
    urllib.parse.urlparse. The attack vector is: A
    specially crafted URL could be incorrectly parsed to
    locate cookies or authentication data and send that
    information to a different host than when parsed
    correctly.(CVE-2019-9636)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1434
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected python packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tkinter");
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

pkgs = ["python-2.7.5-69.h19",
        "python-devel-2.7.5-69.h19",
        "python-libs-2.7.5-69.h19",
        "python-tools-2.7.5-69.h19",
        "tkinter-2.7.5-69.h19"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python");
}
