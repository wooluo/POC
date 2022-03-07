#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1644-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121423);
  script_version("1.3");
  script_cvs_date("Date: 2019/02/06 11:41:38");

  script_cve_id("CVE-2018-19788", "CVE-2019-6133");

  script_name(english:"Debian DLA-1644-1 : policykit-1 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were found in Policykit, a framework for managing
administrative policies and privileges :

CVE-2018-19788

It was discovered that incorrect processing of very high UIDs in
Policykit could result in authentication bypass.

CVE-2019-6133

Jann Horn of Google found that Policykit doesn't properly check if a
process is already authenticated, which can lead to an authentication
reuse by a different user.

For Debian 8 'Jessie', these problems have been fixed in version
0.105-15~deb8u4.

We recommend that you upgrade your policykit-1 packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/01/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/policykit-1"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-polkit-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolkit-agent-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolkit-agent-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolkit-backend-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolkit-backend-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolkit-gobject-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolkit-gobject-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:policykit-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:policykit-1-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/29");
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
if (deb_check(release:"8.0", prefix:"gir1.2-polkit-1.0", reference:"0.105-15~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libpolkit-agent-1-0", reference:"0.105-15~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libpolkit-agent-1-dev", reference:"0.105-15~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libpolkit-backend-1-0", reference:"0.105-15~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libpolkit-backend-1-dev", reference:"0.105-15~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libpolkit-gobject-1-0", reference:"0.105-15~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libpolkit-gobject-1-dev", reference:"0.105-15~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"policykit-1", reference:"0.105-15~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"policykit-1-doc", reference:"0.105-15~deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
