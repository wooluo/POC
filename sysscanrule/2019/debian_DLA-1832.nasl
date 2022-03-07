#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1832-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126220);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/25  9:40:37");

  script_name(english:"Debian DLA-1832-1 : libvirt security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in libvirt, an abstraction API for
different underlying virtualisation mechanisms provided by the kernel,
etc.

  - CVE-2019-10161: Prevent an vulnerability where readonly
    clients could use the API to specify an arbitrary path
    which would be accessed with the permissions of the
    libvirtd process. An attacker with access to the
    libvirtd socket could use this to probe the existence of
    arbitrary files, cause a denial of service or otherwise
    cause libvirtd to execute arbitrary programs.

  - CVE-2019-10167: Prevent an arbitrary code execution
    vulnerability via the API where a user-specified binary
    used to probe the domain's capabilities. read-only
    clients could specify an arbitrary path for this
    argument, causing libvirtd to execute a crafted
    executable with its own privileges.

For Debian 8 'Jessie', these issues have been fixed in libvirt version
1.2.9-9+deb8u7.

We recommend that you upgrade your libvirt packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/06/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libvirt"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-daemon-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt0-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/24");
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
if (deb_check(release:"8.0", prefix:"libvirt-bin", reference:"1.2.9-9+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-clients", reference:"1.2.9-9+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-daemon", reference:"1.2.9-9+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-daemon-system", reference:"1.2.9-9+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-dev", reference:"1.2.9-9+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-doc", reference:"1.2.9-9+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt-sanlock", reference:"1.2.9-9+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt0", reference:"1.2.9-9+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"libvirt0-dbg", reference:"1.2.9-9+deb8u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
