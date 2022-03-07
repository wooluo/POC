#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4467. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126013);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/21 12:43:08");

  script_cve_id("CVE-2019-12735");
  script_xref(name:"DSA", value:"4467");

  script_name(english:"Debian DSA-4467-1 : vim - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"User 'Arminius' discovered a vulnerability in Vim, an enhanced version
of the standard UNIX editor Vi (Vi IMproved). The 'Common
vulnerabilities and exposures project' identifies the following
problem :

Editors typically provide a way to embed editor configuration commands
(aka modelines) which are executed once a file is opened, while
harmful commands are filtered by a sandbox mechanism. It was
discovered that the 'source'command (used to include and execute
another file) was not filtered, allowing shell command execution with
a carefully crafted file opened in Vim."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/vim"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/vim"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4467"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vim packages.

For the stable distribution (stretch), this problem has been fixed in
version 2:8.0.0197-4+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/19");
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
if (deb_check(release:"9.0", prefix:"vim", reference:"2:8.0.0197-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"vim-athena", reference:"2:8.0.0197-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"vim-common", reference:"2:8.0.0197-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"vim-doc", reference:"2:8.0.0197-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"vim-gnome", reference:"2:8.0.0197-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"vim-gtk", reference:"2:8.0.0197-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"vim-gtk3", reference:"2:8.0.0197-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"vim-gui-common", reference:"2:8.0.0197-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"vim-nox", reference:"2:8.0.0197-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"vim-runtime", reference:"2:8.0.0197-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"vim-tiny", reference:"2:8.0.0197-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"xxd", reference:"2:8.0.0197-4+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
