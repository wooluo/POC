#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4471. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126224);
  script_version("1.5");
  script_cvs_date("Date: 2019/08/13 10:54:56");

  script_cve_id("CVE-2019-11707", "CVE-2019-11708");
  script_xref(name:"DSA", value:"4471");

  script_name(english:"Debian DSA-4471-1 : thunderbird - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been found in Thunderbird which may lead
to the execution of arbitrary code if malformed email messages are
read."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/thunderbird"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/thunderbird"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4471"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the thunderbird packages.

For the stable distribution (stretch), these problems have been fixed
in version 1:60.7.2-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
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
if (deb_check(release:"9.0", prefix:"calendar-google-provider", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-dbg", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-dev", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-all", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-ar", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-ast", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-be", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-bg", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-bn-bd", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-br", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-ca", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-cs", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-da", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-de", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-dsb", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-el", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-en-gb", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-es-ar", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-es-es", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-et", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-eu", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-fi", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-fr", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-fy-nl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-ga-ie", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-gd", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-gl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-he", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-hr", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-hsb", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-hu", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-hy-am", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-id", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-is", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-it", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-ja", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-kab", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-ko", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-lt", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-nb-no", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-nl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-nn-no", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-pa-in", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-pl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-pt-br", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-pt-pt", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-rm", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-ro", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-ru", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-si", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-sk", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-sl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-sq", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-sr", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-sv-se", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-ta-lk", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-tr", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-uk", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-vi", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-zh-cn", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"icedove-l10n-zh-tw", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-extension", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-ar", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-ast", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-be", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-bg", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-bn-bd", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-br", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-ca", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-cs", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-cy", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-da", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-de", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-dsb", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-el", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-en-gb", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-es-ar", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-es-es", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-et", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-eu", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-fi", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-fr", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-fy-nl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-ga-ie", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-gd", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-gl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-he", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-hr", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-hsb", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-hu", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-hy-am", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-id", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-is", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-it", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-ja", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-kab", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-ko", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-lt", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-nb-no", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-nl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-nn-no", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-pa-in", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-pl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-pt-br", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-pt-pt", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-rm", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-ro", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-ru", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-si", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-sk", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-sl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-sq", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-sr", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-sv-se", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-ta-lk", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-tr", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-uk", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-vi", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-zh-cn", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"iceowl-l10n-zh-tw", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-ar", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-ast", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-be", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-bg", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-bn-bd", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-br", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-ca", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-cs", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-cy", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-da", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-de", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-dsb", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-el", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-en-gb", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-es-ar", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-es-es", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-et", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-eu", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-fi", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-fr", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-fy-nl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-ga-ie", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-gd", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-gl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-he", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-hr", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-hsb", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-hu", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-hy-am", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-id", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-is", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-it", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-ja", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-kab", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-ko", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-lt", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-nb-no", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-nl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-nn-no", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-pa-in", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-pl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-pt-br", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-pt-pt", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-rm", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-ro", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-ru", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-si", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-sk", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-sl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-sq", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-sr", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-sv-se", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-ta-lk", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-tr", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-uk", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-vi", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-zh-cn", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lightning-l10n-zh-tw", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-dbg", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-dev", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-all", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-ar", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-ast", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-be", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-bg", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-bn-bd", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-br", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-ca", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-cs", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-da", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-de", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-dsb", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-el", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-en-gb", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-es-ar", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-es-es", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-et", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-eu", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-fi", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-fr", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-fy-nl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-ga-ie", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-gd", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-gl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-he", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-hr", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-hsb", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-hu", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-hy-am", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-id", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-is", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-it", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-ja", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-kab", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-ko", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-lt", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-nb-no", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-nl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-nn-no", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-pa-in", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-pl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-pt-br", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-pt-pt", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-rm", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-ro", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-ru", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-si", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-sk", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-sl", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-sq", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-sr", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-sv-se", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-ta-lk", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-tr", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-uk", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-vi", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-zh-cn", reference:"1:60.7.2-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"thunderbird-l10n-zh-tw", reference:"1:60.7.2-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
