#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4504. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128066);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/22 12:32:33");

  script_cve_id("CVE-2019-13602", "CVE-2019-13962", "CVE-2019-14437", "CVE-2019-14438", "CVE-2019-14498", "CVE-2019-14533", "CVE-2019-14534", "CVE-2019-14535", "CVE-2019-14776", "CVE-2019-14777", "CVE-2019-14778", "CVE-2019-14970");
  script_xref(name:"DSA", value:"4504");

  script_name(english:"Debian DSA-4504-1 : vlc - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues were discovered in the VLC media player,
which could result in the execution of arbitrary code or denial of
service if a malformed file/stream is processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/vlc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/vlc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/vlc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4504"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vlc packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 3.0.8-0+deb9u1.

For the stable distribution (buster), these problems have been fixed
in version 3.0.8-0+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vlc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/22");
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
if (deb_check(release:"10.0", prefix:"libvlc-bin", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libvlc-dev", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libvlc5", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libvlccore-dev", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libvlccore9", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-bin", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-data", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-l10n", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-access-extra", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-base", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-fluidsynth", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-jack", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-notify", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-qt", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-samba", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-skins2", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-svg", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-video-output", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-video-splitter", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-visualization", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"vlc-plugin-zvbi", reference:"3.0.8-0+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlc-bin", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlc-dev", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlc5", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlccore-dev", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvlccore8", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-bin", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-data", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-l10n", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-nox", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-access-extra", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-base", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-fluidsynth", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-jack", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-notify", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-qt", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-samba", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-sdl", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-skins2", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-svg", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-video-output", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-video-splitter", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-visualization", reference:"3.0.8-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"vlc-plugin-zvbi", reference:"3.0.8-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
