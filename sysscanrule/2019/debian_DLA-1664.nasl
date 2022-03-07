#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1664-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121626);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/27 11:44:33");

  script_cve_id("CVE-2019-6486");

  script_name(english:"Debian DLA-1664-1 : golang security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there was a denial of service vulnerability or
possibly even the ability to conduct private key recovery attacks
within in the elliptic curve cryptography handling in the Go
programming language libraries.

For Debian 8 'Jessie', this issue has been fixed in golang version
2:1.3.3-1+deb8u1.

We recommend that you upgrade your golang packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/02/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/golang"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-go-darwin-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-go-darwin-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-go-freebsd-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-go-freebsd-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-go-freebsd-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-go-linux-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-go-linux-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-go-linux-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-go-netbsd-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-go-netbsd-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-go-windows-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-go-windows-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kate-syntax-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-syntax-go");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/07");
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
if (deb_check(release:"8.0", prefix:"golang", reference:"2:1.3.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"golang-doc", reference:"2:1.3.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"golang-go", reference:"2:1.3.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"golang-go-darwin-386", reference:"2:1.3.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"golang-go-darwin-amd64", reference:"2:1.3.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"golang-go-freebsd-386", reference:"2:1.3.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"golang-go-freebsd-amd64", reference:"2:1.3.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"golang-go-freebsd-arm", reference:"2:1.3.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"golang-go-linux-386", reference:"2:1.3.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"golang-go-linux-amd64", reference:"2:1.3.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"golang-go-linux-arm", reference:"2:1.3.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"golang-go-netbsd-386", reference:"2:1.3.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"golang-go-netbsd-amd64", reference:"2:1.3.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"golang-go-windows-386", reference:"2:1.3.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"golang-go-windows-amd64", reference:"2:1.3.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"golang-mode", reference:"2:1.3.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"golang-src", reference:"2:1.3.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kate-syntax-go", reference:"2:1.3.3-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"vim-syntax-go", reference:"2:1.3.3-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
