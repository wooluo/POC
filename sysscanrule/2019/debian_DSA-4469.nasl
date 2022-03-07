#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4469. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126128);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:38");

  script_cve_id("CVE-2019-10161", "CVE-2019-10167");
  script_xref(name:"DSA", value:"4469");

  script_name(english:"Debian DSA-4469-1 : libvirt - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in Libvirt, a virtualisation
abstraction library, allowing an API client with read-only permissions
to execute arbitrary commands via the virConnectGetDomainCapabilities
API, or read or execute arbitrary files via the
virDomainSaveImageGetXMLDesc API.

Additionally the libvirt's cpu map was updated to make addressing
CVE-2018-3639, CVE-2017-5753, CVE-2017-5715, CVE-2018-12126,
CVE-2018-12127, CVE-2018-12130 and CVE-2019-11091 easier by supporting
the md-clear, ssbd, spec-ctrl and ibpb CPU features when picking CPU
models without having to fall back to host-passthrough."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-3639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-12126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-12127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-12130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-11091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/libvirt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libvirt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4469"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libvirt packages.

For the stable distribution (stretch), these problems have been fixed
in version 3.0.0-4+deb9u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/24");
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
if (deb_check(release:"9.0", prefix:"libnss-libvirt", reference:"3.0.0-4+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt-clients", reference:"3.0.0-4+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt-daemon", reference:"3.0.0-4+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt-daemon-system", reference:"3.0.0-4+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt-dev", reference:"3.0.0-4+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt-doc", reference:"3.0.0-4+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt-sanlock", reference:"3.0.0-4+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libvirt0", reference:"3.0.0-4+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
