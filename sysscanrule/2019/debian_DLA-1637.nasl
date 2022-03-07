#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1637-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121314);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/15 14:20:30");

  script_cve_id("CVE-2019-3462");

  script_name(english:"Debian DLA-1637-1 : apt security update (amended)");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"(amended to refer to jessie in the sources.list entry below, instead
of stable)

Max Justicz discovered a vulnerability in APT, the high level package
manager. The code handling HTTP redirects in the HTTP transport method
doesn't properly sanitize fields transmitted over the wire. This
vulnerability could be used by an attacker located as a
man-in-the-middle between APT and a mirror to inject malicous content
in the HTTP connection. This content could then be recognized as a
valid package by APT and used later for code execution with root
privileges on the target machine.

Since the vulnerability is present in the package manager itself, it
is recommended to disable redirects in order to prevent exploitation
during this upgrade only, using :

apt -o Acquire::http::AllowRedirect=false update apt -o
Acquire::http::AllowRedirect=false upgrade

This is known to break some proxies when used against
security.debian.org. If that happens, people can switch their security
APT source to use :

deb http://cdn-fastly.deb.debian.org/debian-security jessie/updates
main

For Debian 8 'Jessie', this problem has been fixed in version
1.0.9.8.5.

We recommend that you upgrade your apt packages.

Specific upgrade instructions :

If upgrading using APT without redirect is not possible in your
situation, you can manually download the files (using wget/curl) for
your architecture using the URL provided below, verifying that the
hashes match. Then you can install them using dpkg -i.

Architecture independent files :

http://security.debian.org/debian-security/pool/updates/main/a/apt/apt
-doc_1.0.9.8.5_all.deb Size/SHA256 checksum: 301106
47df9567e45fadcd2a56c0fd3d514d8136f2f206aa7baa47405c6fcb94824ab6
http://security.debian.org/debian-security/pool/updates/main/a/apt/lib
apt-pkg-doc_1.0.9.8.5_all.deb Size/SHA256 checksum: 750506
ce79b2ef272716b8da11f3fd0497ce0b7ee69c9c66d01669e8abbbfdde5e6256

amd64 architecture :

http://security.debian.org/debian-security/pool/updates/main/a/apt/lib
apt-pkg4.12_1.0.9.8.5_amd64.deb Size/SHA256 checksum: 792126
295d9c69854a4cfbcb46001b09b853f5a098a04c986fc5ae01a0124c1c27e6bd
http://security.debian.org/debian-security/pool/updates/main/a/apt/lib
apt-inst1.5_1.0.9.8.5_amd64.deb Size/SHA256 checksum: 168896
f9615532b1577b3d1455fa51839ce91765f2860eb3a6810fb5e0de0c87253030
http://security.debian.org/debian-security/pool/updates/main/a/apt/apt
_1.0.9.8.5_amd64.deb Size/SHA256 checksum: 1109308
4078748632abc19836d045f80f9d6933326065ca1d47367909a0cf7f29e7dfe8
http://security.debian.org/debian-security/pool/updates/main/a/apt/lib
apt-pkg-dev_1.0.9.8.5_amd64.deb Size/SHA256 checksum: 192950
09ef86d178977163b8cf0081d638d74e0a90c805dd77750c1d91354b6840b032
http://security.debian.org/debian-security/pool/updates/main/a/apt/apt
-utils_1.0.9.8.5_amd64.deb Size/SHA256 checksum: 368396
87c55d9ccadcabd59674873c221357c774020c116afd978fb9df6d2d0303abf2
http://security.debian.org/debian-security/pool/updates/main/a/apt/apt
-transport-https_1.0.9.8.5_amd64.deb Size/SHA256 checksum: 137230
f5a17422fd319ff5f6e3ea9a9e87d2508861830120125484130da8c1fd479df2

armel architecture :

http://security.debian.org/debian-security/pool/updates/main/a/apt/lib
apt-pkg4.12_1.0.9.8.5_armel.deb Size/SHA256 checksum: 717002
80fe021d87f2444abdd7c5491e7a4bf9ab9cb2b8e6fa72d308905f4e0aad60d4
http://security.debian.org/debian-security/pool/updates/main/a/apt/lib
apt-inst1.5_1.0.9.8.5_armel.deb Size/SHA256 checksum: 166784
046fb962fa214c5d6acfb7344e7719f8c4898d87bf29ed3cd2115e3f6cdd14e9
http://security.debian.org/debian-security/pool/updates/main/a/apt/apt
_1.0.9.8.5_armel.deb Size/SHA256 checksum: 1067404
f9a257d6aace1f222633e0432abf1d6946bad9dbd0ca18dccb288d50f17b895f
http://security.debian.org/debian-security/pool/updates/main/a/apt/lib
apt-pkg-dev_1.0.9.8.5_armel.deb Size/SHA256 checksum: 193768
4cb226f55132a68a2f5db925ada6147aaf052adb02301fb45fb0c2d1cfce36f0
http://security.debian.org/debian-security/pool/updates/main/a/apt/apt
-utils_1.0.9.8.5_armel.deb Size/SHA256 checksum: 353178
38042838d8bc79642e5389be7d2d2d967cbf316805d4c8c2d6afbe1bc164aacc
http://security.debian.org/debian-security/pool/updates/main/a/apt/apt
-transport-https_1.0.9.8.5_armel.deb Size/SHA256 checksum: 134932
755b6d22f5914f3153a1c15427e5221507b174c0a4c6b860ebd16234c9e9a146

armhf architecture :

http://security.debian.org/debian-security/pool/updates/main/a/apt/lib
apt-pkg4.12_1.0.9.8.5_armhf.deb Size/SHA256 checksum: 734302
0f48f6d0406afdf0bd4d39e90e56460fab3d9b5fa4c91e2dca78ec22caf2fe2a
http://security.debian.org/debian-security/pool/updates/main/a/apt/lib
apt-inst1.5_1.0.9.8.5_armhf.deb Size/SHA256 checksum: 166556
284a1ffd529e1daab3c300be17a20f11450555be9c0af166d9796c18147a03ba
http://security.debian.org/debian-security/pool/updates/main/a/apt/apt
_1.0.9.8.5_armhf.deb Size/SHA256 checksum: 1078212
08d85c30c8e4a6df0dced8e232a6c7639caa231acef4af8fdee2c1e07f0178ba
http://security.debian.org/debian-security/pool/updates/main/a/apt/lib
apt-pkg-dev_1.0.9.8.5_armhf.deb Size/SHA256 checksum: 193796
3a26bd79677b46ce0a992e2ac808c4bbd2d5b3fc37b57fc93c8efa114de1adaa
http://security.debian.org/debian-security/pool/updates/main/a/apt/apt
-utils_1.0.9.8.5_armhf.deb Size/SHA256 checksum: 357074
19dec9ffc0fe4a86d6e61b5213e75c55ae6aaade6f3804f90e2e4034bbdc44d8
http://security.debian.org/debian-security/pool/updates/main/a/apt/apt
-transport-https_1.0.9.8.5_armhf.deb Size/SHA256 checksum: 135072
06ba556c5218e58fd14119e3b08a08f685209a0cbe09f2328bd572cabc580bca

i386 architecture :

http://security.debian.org/debian-security/pool/updates/main/a/apt/lib
apt-pkg4.12_1.0.9.8.5_i386.deb Size/SHA256 checksum: 800840
201b6cf4625ed175e6a024ac1f7ca6c526ca79d859753c125b02cd69e26c349d
http://security.debian.org/debian-security/pool/updates/main/a/apt/lib
apt-inst1.5_1.0.9.8.5_i386.deb Size/SHA256 checksum: 170484
5791661dd4ade72b61086fefdc209bd1f76ac7b7c812d6d4ba951b1a6232f0b9
http://security.debian.org/debian-security/pool/updates/main/a/apt/apt
_1.0.9.8.5_i386.deb Size/SHA256 checksum: 1110418
13c230e9c544b1e67a8da413046bf1728526372170533b1a23e70cc99c40a228
http://security.debian.org/debian-security/pool/updates/main/a/apt/lib
apt-pkg-dev_1.0.9.8.5_i386.deb Size/SHA256 checksum: 193780
c5b1bfa913ea2e2e332c228f5c5fe4dbc11ab334d0551a68ba6e87e94a51ffee
http://security.debian.org/debian-security/pool/updates/main/a/apt/apt
-utils_1.0.9.8.5_i386.deb Size/SHA256 checksum: 371218
1a74b12c8bb6b3968a721f3aa96739073e4fe2ced9302792c533e21535bc9cf4
http://security.debian.org/debian-security/pool/updates/main/a/apt/apt
-transport-https_1.0.9.8.5_i386.deb Size/SHA256 checksum: 139036
32148d92914a97df8bbb9f223e788dcbc7c39e570cf48e6759cb483a65b68666

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cdn-fastly.deb.debian.org/debian-security"
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/apt-doc_1.0.9.8.5_all.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/apt-transport-https_1.0.9.8.5_amd64.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/apt-transport-https_1.0.9.8.5_armel.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/apt-transport-https_1.0.9.8.5_armhf.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/apt-transport-https_1.0.9.8.5_i386.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/apt-utils_1.0.9.8.5_amd64.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/apt-utils_1.0.9.8.5_armel.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/apt-utils_1.0.9.8.5_armhf.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/apt-utils_1.0.9.8.5_i386.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/apt_1.0.9.8.5_amd64.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/apt_1.0.9.8.5_armel.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/apt_1.0.9.8.5_armhf.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/apt_1.0.9.8.5_i386.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-inst1.5_1.0.9.8.5_amd64.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-inst1.5_1.0.9.8.5_armel.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-inst1.5_1.0.9.8.5_armhf.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-inst1.5_1.0.9.8.5_i386.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-pkg-dev_1.0.9.8.5_amd64.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-pkg-dev_1.0.9.8.5_armel.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-pkg-dev_1.0.9.8.5_armhf.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-pkg-dev_1.0.9.8.5_i386.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-pkg-doc_1.0.9.8.5_all.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-pkg4.12_1.0.9.8.5_amd64.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-pkg4.12_1.0.9.8.5_armel.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-pkg4.12_1.0.9.8.5_armhf.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-pkg4.12_1.0.9.8.5_i386.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/01/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/apt"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt-transport-https");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapt-inst1.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapt-pkg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapt-pkg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapt-pkg4.12");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/23");
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
if (deb_check(release:"8.0", prefix:"apt", reference:"1.0.9.8.5")) flag++;
if (deb_check(release:"8.0", prefix:"apt-doc", reference:"1.0.9.8.5")) flag++;
if (deb_check(release:"8.0", prefix:"apt-transport-https", reference:"1.0.9.8.5")) flag++;
if (deb_check(release:"8.0", prefix:"apt-utils", reference:"1.0.9.8.5")) flag++;
if (deb_check(release:"8.0", prefix:"libapt-inst1.5", reference:"1.0.9.8.5")) flag++;
if (deb_check(release:"8.0", prefix:"libapt-pkg-dev", reference:"1.0.9.8.5")) flag++;
if (deb_check(release:"8.0", prefix:"libapt-pkg-doc", reference:"1.0.9.8.5")) flag++;
if (deb_check(release:"8.0", prefix:"libapt-pkg4.12", reference:"1.0.9.8.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
