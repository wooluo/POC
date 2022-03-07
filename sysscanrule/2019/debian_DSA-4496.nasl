#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4496. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127492);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-1010238");
  script_xref(name:"DSA", value:"4496");

  script_name(english:"Debian DSA-4496-1 : pango1.0 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Benno Fuenfstueck discovered that Pango, a library for layout and
rendering of text with an emphasis on internationalization, is prone
to a heap-based buffer overflow flaw in the
pango_log2vis_get_embedding_levels function. An attacker can take
advantage of this flaw for denial of service or potentially the
execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=933860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/pango1.0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/pango1.0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4496"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pango1.0 packages.

For the stable distribution (buster), this problem has been fixed in
version 1.42.4-7~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pango1.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/11");
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
if (deb_check(release:"10.0", prefix:"gir1.2-pango-1.0", reference:"1.42.4-7~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libpango-1.0-0", reference:"1.42.4-7~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libpango1.0-0", reference:"1.42.4-7~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libpango1.0-dev", reference:"1.42.4-7~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libpango1.0-doc", reference:"1.42.4-7~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libpango1.0-udeb", reference:"1.42.4-7~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libpangocairo-1.0-0", reference:"1.42.4-7~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libpangoft2-1.0-0", reference:"1.42.4-7~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libpangoxft-1.0-0", reference:"1.42.4-7~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"pango1.0-tests", reference:"1.42.4-7~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"pango1.0-tools", reference:"1.42.4-7~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
