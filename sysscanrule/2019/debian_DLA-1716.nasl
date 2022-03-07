#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1716-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122928);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/15 14:20:30");

  script_cve_id("CVE-2019-9187");

  script_name(english:"Debian DLA-1716-1 : ikiwiki security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The ikiwiki maintainers discovered that the aggregate plugin did not
use LWPx::ParanoidAgent. On sites where the aggregate plugin is
enabled, authorized wiki editors could tell ikiwiki to fetch
potentially undesired URIs even if LWPx::ParanoidAgent was installed :

local files via file: URIs other URI schemes that might be misused by
attackers, such as gopher: hosts that resolve to loopback IP addresses
(127.x.x.x) hosts that resolve to RFC 1918 IP addresses (192.168.x.x
etc.)

This could be used by an attacker to publish information that should
not have been accessible, cause denial of service by requesting
'tarpit' URIs that are slow to respond, or cause undesired
side-effects if local web servers implement 'unsafe' GET requests.
(CVE-2019-9187)

Additionally, if liblwpx-paranoidagent-perl is not installed, the
blogspam, openid and pinger plugins would fall back to LWP, which is
susceptible to similar attacks. This is unlikely to be a practical
problem for the blogspam plugin because the URL it requests is under
the control of the wiki administrator, but the openid plugin can
request URLs controlled by unauthenticated remote users, and the
pinger plugin can request URLs controlled by authorized wiki editors.

This is addressed in ikiwiki 3.20190228 as follows, with the same
fixes backported to Debian 9 in version 3.20170111.1 :

  - URI schemes other than http: and https: are not
    accepted, preventing access to file:, gopher:, etc.

  - If a proxy is configured in the ikiwiki setup file, it
    is used for all outgoing http: and https: requests. In
    this case the proxy is responsible for blocking any
    requests that are undesired, including loopback or RFC
    1918 addresses.

  - If a proxy is not configured, and
    liblwpx-paranoidagent-perl is installed, it will be
    used. This prevents loopback and RFC 1918 IP addresses,
    and sets a timeout to avoid denial of service via
    'tarpit' URIs.

  - Otherwise, the ordinary LWP user-agent will be used.
    This allows requests to loopback and RFC 1918 IP
    addresses, and has less robust timeout behaviour. We are
    not treating this as a vulnerability: if this behaviour
    is not acceptable for your site, please make sure to
    install LWPx::ParanoidAgent or disable the affected
    plugins.

For Debian 8 'Jessie', this problem has been fixed in version
3.20141016.4+deb8u1.

We recommend that you upgrade your ikiwiki packages. In addition it is
also recommended that you have liblwpx-paranoidagent-perl installed,
which listed in the recommends field of ikiwiki.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ikiwiki"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected ikiwiki package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ikiwiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/18");
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
if (deb_check(release:"8.0", prefix:"ikiwiki", reference:"3.20141016.4+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
