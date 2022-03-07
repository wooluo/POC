#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124905);
  script_version("1.5");
  script_cvs_date("Date: 2019/06/27 13:33:25");

  script_cve_id(
    "CVE-2016-10167",
    "CVE-2016-10168",
    "CVE-2017-7890",
    "CVE-2018-20783",
    "CVE-2019-6977",
    "CVE-2019-9020",
    "CVE-2019-9021",
    "CVE-2019-9023",
    "CVE-2019-9024",
    "CVE-2019-9637"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : php (EulerOS-SA-2019-1402)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the php packages installed, the EulerOS
Virtualization for ARM 64 installation on the remote host is affected
by the following vulnerabilities :

  - An issue was discovered in PHP before 5.6.40, 7.x
    before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before
    7.3.1. Invalid input to the function xmlrpc_decode()
    can lead to an invalid memory access (heap out of
    bounds read or read after free). This is related to
    xml_elem_parse_buf in
    ext/xmlrpc/libxmlrpc/xml_element.c.(CVE-2019-9020)

  - In PHP before 5.6.39, 7.x before 7.0.33, 7.1.x before
    7.1.25, and 7.2.x before 7.2.13, a buffer over-read in
    PHAR reading functions may allow an attacker to read
    allocated or unallocated memory past the actual data
    when trying to parse a .phar file. This is related to
    phar_parse_pharfile in ext/phar/phar.c.(CVE-2018-20783)

  - An issue was discovered in PHP before 5.6.40, 7.x
    before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before
    7.3.1. A number of heap-based buffer over-read
    instances are present in mbstring regular expression
    functions when supplied with invalid multibyte data.
    These occur in ext/mbstring/oniguruma/regcomp.c,
    ext/mbstring/oniguruma/regexec.c,
    ext/mbstring/oniguruma/regparse.c,
    ext/mbstring/oniguruma/enc/unicode.c, and
    ext/mbstring/oniguruma/src/utf32_be.c when a multibyte
    regular expression pattern contains invalid multibyte
    sequences.(CVE-2019-9023)

  - An issue was discovered in PHP before 5.6.40, 7.x
    before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before
    7.3.1. A heap-based buffer over-read in PHAR reading
    functions in the PHAR extension may allow an attacker
    to read allocated or unallocated memory past the actual
    data when trying to parse the file name, a different
    vulnerability than CVE-2018-20783. This is related to
    phar_detect_phar_fname_ext in
    ext/phar/phar.c.(CVE-2019-9021)

  - An issue was discovered in PHP before 7.1.27, 7.2.x
    before 7.2.16, and 7.3.x before 7.3.3. Due to the way
    rename() across filesystems is implemented, it is
    possible that file being renamed is briefly available
    with wrong permissions while the rename is ongoing,
    thus enabling unauthorized users to access the
    data.(CVE-2019-9637)

  - An issue was discovered in PHP before 5.6.40, 7.x
    before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before
    7.3.1. xmlrpc_decode() can allow a hostile XMLRPC
    server to cause PHP to read memory outside of allocated
    areas in base64_decode_xmlrpc in
    ext/xmlrpc/libxmlrpc/base64.c.(CVE-2019-9024)

  - An integer overflow flaw, leading to a heap-based
    buffer overflow was found in the way libgd read some
    specially-crafted gd2 files. A remote attacker could
    use this flaw to crash an application compiled with
    libgd or in certain cases execute arbitrary code with
    the privileges of the user running that
    application.(CVE-2016-1016)

  - A null pointer dereference flaw was found in libgd. An
    attacker could use a specially-crafted .gd2 file to
    cause an application linked with libgd to crash,
    leading to denial of service.(CVE-2016-10167)

  - A data leak was found in gdImageCreateFromGifCtx() in
    GD Graphics Library used in PHP before 5.6.31 and
    7.1.7. An attacker could craft a malicious GIF image
    and read up to 762 bytes from stack.(CVE-2017-7890)

  - gdImageColorMatch in gd_color_match.c in the GD
    Graphics Library (aka LibGD) 2.2.5, as used in the
    imagecolormatch function in PHP before 5.6.40, 7.x
    before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before
    7.3.1, has a heap-based buffer overflow. This can be
    exploited by an attacker who is able to trigger
    imagecolormatch calls with crafted image
    data.(CVE-2019-6977)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1402
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
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
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["php-5.4.16-45.h8",
        "php-cli-5.4.16-45.h8",
        "php-common-5.4.16-45.h8"];

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
