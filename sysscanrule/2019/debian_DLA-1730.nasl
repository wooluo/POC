#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1730-4. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123135);
  script_version("1.4");
  script_cvs_date("Date: 2019/08/12 17:35:38");

  script_cve_id("CVE-2019-3860");

  script_name(english:"Debian DLA-1730-4 : libssh2 regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several more boundary checks have been backported to libssh2's
src/sftp.c. Furthermore, all boundary checks in src/sftp.c now result
in an LIBSSH2_ERROR_BUFFER_TOO_SMALL error code, rather than a
LIBSSH2_ERROR_ OUT_OF_BOUNDARY error code.

As a side note, it was discovered that libssh2's SFTP implementation
from Debian jessie only works well against OpenSSH SFTP servers from
Debian wheezy, tests against newer OpenSSH versions (such as available
in Debian jessie and beyond) interim-fail with SFTP protocol error
'Error opening remote file'. Operation might continue after this
error, this depends on application implementations.

For Debian 8 'Jessie', this problem has been fixed in version
1.4.3-4.1+deb8u5.

We recommend that you upgrade your libssh2 packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/07/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libssh2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssh2-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssh2-1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssh2-1-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
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
if (deb_check(release:"8.0", prefix:"libssh2-1", reference:"1.4.3-4.1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libssh2-1-dbg", reference:"1.4.3-4.1+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libssh2-1-dev", reference:"1.4.3-4.1+deb8u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
