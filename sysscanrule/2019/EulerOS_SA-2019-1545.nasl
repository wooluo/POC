#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124998);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/27 13:33:26");

  script_cve_id(
    "CVE-2013-6420",
    "CVE-2015-2301",
    "CVE-2015-3307",
    "CVE-2015-3330",
    "CVE-2015-3411",
    "CVE-2015-4147",
    "CVE-2015-4600",
    "CVE-2016-7478",
    "CVE-2018-20783",
    "CVE-2019-9020",
    "CVE-2019-9021",
    "CVE-2019-9023",
    "CVE-2019-9024",
    "CVE-2019-9637",
    "CVE-2019-9640"
  );
  script_bugtraq_id(
    64225,
    73037,
    73357,
    74204,
    74413,
    74703,
    75255
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : php (EulerOS-SA-2019-1545)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the php packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - A flaws was discovered in the way PHP performed object
    unserialization. Specially crafted input processed by
    the unserialize() function could cause a PHP
    application to crash or, possibly, execute arbitrary
    code.(CVE-2015-4147)

  - An invalid free flaw was found in the way PHP's Phar
    extension parsed Phar archives. A specially crafted
    archive could cause PHP to crash or, possibly, execute
    arbitrary code when opened.(CVE-2015-3307)

  - A flaw was found in the way the PHP module for the
    Apache httpd web server handled pipelined requests. A
    remote attacker could use this flaw to trigger the
    execution of a PHP script in a deinitialized
    interpreter, causing it to crash or, possibly, execute
    arbitrary code.(CVE-2015-3330)

  - Multiple flaws were discovered in the way PHP's Soap
    extension performed object unserialization. Specially
    crafted input processed by the unserialize() function
    could cause a PHP application to disclose portion of
    its memory or crash.(CVE-2015-4600)

  - Zend/zend_exceptions.c in PHP, possibly 5.x before
    5.6.28 and 7.x before 7.0.13, allows remote attackers
    to cause a denial of service (infinite loop) via a
    crafted Exception object in serialized data, a related
    issue to CVE-2015-8876.(CVE-2016-7478)

  - It was found that certain PHP functions did not
    properly handle file names containing a NULL character.
    A remote attacker could possibly use this flaw to make
    a PHP script access unexpected files and bypass
    intended file system access
    restrictions.(CVE-2015-3411)

  - The asn1_time_to_time_t function in
    ext/openssl/openssl.c in PHP before 5.3.28, 5.4.x
    before 5.4.23, and 5.5.x before 5.5.7 does not properly
    parse (1) notBefore and (2) notAfter timestamps in
    X.509 certificates, which allows remote attackers to
    execute arbitrary code or cause a denial of service
    (memory corruption) via a crafted certificate that is
    not properly handled by the openssl_x509_parse
    function.(CVE-2013-6420)

  - A use-after-free flaw was found in PHP's phar (PHP
    Archive) paths implementation. A malicious script
    author could possibly use this flaw to disclose certain
    portions of server memory.(CVE-2015-2301)

  - In PHP before 5.6.39, 7.x before 7.0.33, 7.1.x before
    7.1.25, and 7.2.x before 7.2.13, a buffer over-read in
    PHAR reading functions may allow an attacker to read
    allocated or unallocated memory past the actual data
    when trying to parse a .phar file. This is related to
    phar_parse_pharfile in ext/phar/phar.c.(CVE-2018-20783)

  - An issue was discovered in PHP before 5.6.40, 7.x
    before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before
    7.3.1. Invalid input to the function xmlrpc_decode()
    can lead to an invalid memory access (heap out of
    bounds read or read after free). This is related to
    xml_elem_parse_buf in
    ext/xmlrpc/libxmlrpc/xml_element.c.(CVE-2019-9020)

  - An issue was discovered in PHP before 5.6.40, 7.x
    before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before
    7.3.1. A heap-based buffer over-read in PHAR reading
    functions in the PHAR extension may allow an attacker
    to read allocated or unallocated memory past the actual
    data when trying to parse the file name, a different
    vulnerability than CVE-2018-20783. This is related to
    phar_detect_phar_fname_ext in
    ext/phar/phar.c.(CVE-2019-9021)

  - An issue was discovered in PHP before 5.6.40, 7.x
    before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before
    7.3.1. A heap-based buffer over-read in PHAR reading
    functions in the PHAR extension may allow an attacker
    to read allocated or unallocated memory past the actual
    data when trying to parse the file name, a different
    vulnerability than CVE-2018-20783. This is related to
    phar_detect_phar_fname_ext in
    ext/phar/phar.c.(CVE-2019-9023)

  - An issue was discovered in PHP before 5.6.40, 7.x
    before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before
    7.3.1. A heap-based buffer over-read in PHAR reading
    functions in the PHAR extension may allow an attacker
    to read allocated or unallocated memory past the actual
    data when trying to parse the file name, a different
    vulnerability than CVE-2018-20783. This is related to
    phar_detect_phar_fname_ext in
    ext/phar/phar.c.(CVE-2019-9024)

  - An issue was discovered in PHP before 7.1.27, 7.2.x
    before 7.2.16, and 7.3.x before 7.3.3. Due to the way
    rename() across filesystems is implemented, it is
    possible that file being renamed is briefly available
    with wrong permissions while the rename is ongoing,
    thus enabling unauthorized users to access the
    data.(CVE-2019-9637)

  - An issue was discovered in the EXIF component in PHP
    before 7.1.27, 7.2.x before 7.2.16, and 7.3.x before
    7.3.3. There is an Invalid Read in
    exif_process_SOFn.(CVE-2019-9640)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1545
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-common");
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

pkgs = ["php-5.4.16-45.h9",
        "php-cli-5.4.16-45.h9",
        "php-common-5.4.16-45.h9"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
