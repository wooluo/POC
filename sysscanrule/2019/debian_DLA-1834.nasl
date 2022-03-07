#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1834-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126222);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/15 14:20:30");

  script_cve_id("CVE-2018-14647", "CVE-2019-10160", "CVE-2019-5010", "CVE-2019-9636", "CVE-2019-9740", "CVE-2019-9947", "CVE-2019-9948");

  script_name(english:"Debian DLA-1834-1 : python2.7 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in Python, an interactive
high-level object-oriented language, including 

CVE-2018-14647

Python's elementtree C accelerator failed to initialise Expat's hash
salt during initialization. This could make it easy to conduct denial
of service attacks against Expat by constructing an XML document that
would cause pathological hash collisions in Expat's internal data
structures, consuming large amounts CPU and RAM.

CVE-2019-5010

NULL pointer dereference using a specially crafted X509 certificate.

CVE-2019-9636

Improper Handling of Unicode Encoding (with an incorrect netloc)
during NFKC normalization resulting in information disclosure
(credentials, cookies, etc. that are cached against a given hostname).
A specially crafted URL could be incorrectly parsed to locate cookies
or authentication data and send that information to a different host
than when parsed correctly.

CVE-2019-9740

An issue was discovered in urllib2 where CRLF injection is possible if
the attacker controls a url parameter, as demonstrated by the first
argument to urllib.request.urlopen with \r\n (specifically in the
query string after a ? character) followed by an HTTP header or a
Redis command.

CVE-2019-9947

An issue was discovered in urllib2 where CRLF injection is possible if
the attacker controls a url parameter, as demonstrated by the first
argument to urllib.request.urlopen with \r\n (specifically in the path
component of a URL that lacks a ? character) followed by an HTTP
header or a Redis command. This is similar to the CVE-2019-9740 query
string issue.

CVE-2019-9948

urllib supports the local_file: scheme, which makes it easier for
remote attackers to bypass protection mechanisms that blacklist file:
URIs, as demonstrated by triggering a
urllib.urlopen('local_file:///etc/passwd') call.

CVE-2019-10160

A security regression of CVE-2019-9636 was discovered which still
allows an attacker to exploit CVE-2019-9636 by abusing the user and
password parts of a URL. When an application parses user-supplied URLs
to store cookies, authentication credentials, or other kind of
information, it is possible for an attacker to provide specially
crafted URLs to make the application locate host-related information
(e.g. cookies, authentication data) and send them to a different host
than where it should, unlike if the URLs had been correctly parsed.
The result of an attack may vary based on the application.

For Debian 8 'Jessie', these problems have been fixed in version
2.7.9-2+deb8u3.

We recommend that you upgrade your python2.7 packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/06/msg00022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/python2.7"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:idle-python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/25");
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
if (deb_check(release:"8.0", prefix:"idle-python2.7", reference:"2.7.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libpython2.7", reference:"2.7.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libpython2.7-dbg", reference:"2.7.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libpython2.7-dev", reference:"2.7.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libpython2.7-minimal", reference:"2.7.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libpython2.7-stdlib", reference:"2.7.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libpython2.7-testsuite", reference:"2.7.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"python2.7", reference:"2.7.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"python2.7-dbg", reference:"2.7.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"python2.7-dev", reference:"2.7.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"python2.7-doc", reference:"2.7.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"python2.7-examples", reference:"2.7.9-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"python2.7-minimal", reference:"2.7.9-2+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
