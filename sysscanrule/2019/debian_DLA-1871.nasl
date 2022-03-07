#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1871-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127480);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2017-11109", "CVE-2017-17087", "CVE-2019-12735");

  script_name(english:"Debian DLA-1871-1 : vim security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several minor issues have been fixed in vim, a highly configurable
text editor.

CVE-2017-11109

Vim allows attackers to cause a denial of service (invalid free) or
possibly have unspecified other impact via a crafted source (aka -S)
file.

CVE-2017-17087

Vim sets the group ownership of a .swp file to the editor's primary
group (which may be different from the group ownership of the original
file), which allows local users to obtain sensitive information by
leveraging an applicable group membership.

CVE-2019-12735

Vim did not restrict the `:source!` command when executed in a
sandbox.

For Debian 8 'Jessie', these problems have been fixed in version
2:7.4.488-7+deb8u4.

We recommend that you upgrade your vim packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/vim"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-athena");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gui-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-lesstif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-tiny");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
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
if (deb_check(release:"8.0", prefix:"vim", reference:"2:7.4.488-7+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"vim-athena", reference:"2:7.4.488-7+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"vim-common", reference:"2:7.4.488-7+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"vim-dbg", reference:"2:7.4.488-7+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"vim-doc", reference:"2:7.4.488-7+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"vim-gnome", reference:"2:7.4.488-7+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"vim-gtk", reference:"2:7.4.488-7+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"vim-gui-common", reference:"2:7.4.488-7+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"vim-lesstif", reference:"2:7.4.488-7+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"vim-nox", reference:"2:7.4.488-7+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"vim-runtime", reference:"2:7.4.488-7+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"vim-tiny", reference:"2:7.4.488-7+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
