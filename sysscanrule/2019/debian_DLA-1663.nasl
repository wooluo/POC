#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1663-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122036);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/02 21:54:16");

  script_cve_id("CVE-2016-0772", "CVE-2016-5636", "CVE-2016-5699", "CVE-2018-20406", "CVE-2019-5010");

  script_name(english:"Debian DLA-1663-1 : python3.4 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This DLA fixes a a problem parsing x509 certificates, an pickle
integer overflow, and some other minor issues :

CVE-2016-0772

The smtplib library in CPython does not return an error when StartTLS
fails, which might allow man-in-the-middle attackers to bypass the TLS
protections by leveraging a network position between the client and
the registry to block the StartTLS command, aka a 'StartTLS stripping
attack.'

CVE-2016-5636

Integer overflow in the get_data function in zipimport.c in CPython
allows remote attackers to have unspecified impact via a negative data
size value, which triggers a heap-based buffer overflow.

CVE-2016-5699

CRLF injection vulnerability in the HTTPConnection.putheader function
in urllib2 and urllib in CPython allows remote attackers to inject
arbitrary HTTP headers via CRLF sequences in a URL.

CVE-2018-20406

Modules/_pickle.c has an integer overflow via a large LONG_BINPUT
value that is mishandled during a 'resize to twice the size' attempt.
This issue might cause memory exhaustion, but is only relevant if the
pickle format is used for serializing tens or hundreds of gigabytes of
data.

CVE-2019-5010

NULL pointer dereference using a specially crafted X509 certificate.

For Debian 8 'Jessie', these problems have been fixed in version
3.4.2-1+deb8u2.

We recommend that you upgrade your python3.4 packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/02/msg00011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/python3.4"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:idle-python3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.4-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.4-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.4-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.4-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.4-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.4-venv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"idle-python3.4", reference:"3.4.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpython3.4", reference:"3.4.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpython3.4-dbg", reference:"3.4.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpython3.4-dev", reference:"3.4.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpython3.4-minimal", reference:"3.4.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpython3.4-stdlib", reference:"3.4.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpython3.4-testsuite", reference:"3.4.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python3.4", reference:"3.4.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python3.4-dbg", reference:"3.4.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python3.4-dev", reference:"3.4.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python3.4-doc", reference:"3.4.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python3.4-examples", reference:"3.4.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python3.4-minimal", reference:"3.4.2-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python3.4-venv", reference:"3.4.2-1+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
