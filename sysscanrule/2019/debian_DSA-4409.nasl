#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4409. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122957);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/20 10:53:34");

  script_cve_id("CVE-2019-9735");
  script_xref(name:"DSA", value:"4409");

  script_name(english:"Debian DSA-4409-1 : neutron - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Erik Olof Gunnar Andersson discovered that incorrect validation of
port settings in the iptables security group driver of Neutron, the
OpenStack virtual network service, could result in denial of service
in a multi tenant setup."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/neutron"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/neutron"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4409"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the neutron packages.

For the stable distribution (stretch), this problem has been fixed in
version 2:9.1.1-3+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:neutron");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/20");
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
if (deb_check(release:"9.0", prefix:"neutron-common", reference:"2:9.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"neutron-dhcp-agent", reference:"2:9.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"neutron-l3-agent", reference:"2:9.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"neutron-linuxbridge-agent", reference:"2:9.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"neutron-macvtap-agent", reference:"2:9.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"neutron-metadata-agent", reference:"2:9.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"neutron-metering-agent", reference:"2:9.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"neutron-openvswitch-agent", reference:"2:9.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"neutron-plugin-linuxbridge-agent", reference:"2:9.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"neutron-plugin-nec-agent", reference:"2:9.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"neutron-plugin-openvswitch-agent", reference:"2:9.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"neutron-server", reference:"2:9.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"neutron-sriov-agent", reference:"2:9.1.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-neutron", reference:"2:9.1.1-3+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
