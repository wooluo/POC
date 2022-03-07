#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4408. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122933);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/19 11:02:10");

  script_cve_id("CVE-2019-6256", "CVE-2019-7314", "CVE-2019-9215");
  script_xref(name:"DSA", value:"4408");

  script_name(english:"Debian DSA-4408-1 : liblivemedia - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues were discovered in liveMedia, a set of C++
libraries for multimedia streaming which could result in the execution
of arbitrary code or denial of service when parsing a malformed RTSP
stream."
  );
  # https://security-tracker.debian.org/tracker/source-package/liblivemedia
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/liblivemedia"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4408"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the liblivemedia packages.

For the stable distribution (stretch), these problems have been fixed
in version 2016.11.28-1+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblivemedia");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/19");
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
if (deb_check(release:"9.0", prefix:"libbasicusageenvironment1", reference:"2016.11.28-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libgroupsock8", reference:"2016.11.28-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"liblivemedia-dev", reference:"2016.11.28-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"liblivemedia57", reference:"2016.11.28-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libusageenvironment3", reference:"2016.11.28-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"livemedia-utils", reference:"2016.11.28-1+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
