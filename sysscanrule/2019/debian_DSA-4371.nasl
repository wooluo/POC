#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4371. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121317);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/15 14:20:30");

  script_cve_id("CVE-2019-3462");
  script_xref(name:"DSA", value:"4371");

  script_name(english:"Debian DSA-4371-1 : apt - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Max Justicz discovered a vulnerability in APT, the high level package
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

deb http://cdn-fastly.deb.debian.org/debian-security stable/updates
main"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cdn-fastly.deb.debian.org/debian-security"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9.dsc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9.tar.xz"
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-doc_1.4.9_all.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-doc_1.4.9_all.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-transport-https_1.4.9_amd64.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_amd64.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_amd64.deb"
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4.9_amd64.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4.9_amd64.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.9_amd64.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-transport-https_1.4.9_arm64.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_arm64.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_arm64.deb"
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4.9_arm64.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4.9_arm64.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.9_arm64.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-transport-https_1.4.9_armel.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_armel.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_armel.deb"
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4.9_armel.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4.9_armel.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.9_armel.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-transport-https_1.4.9_armhf.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_armhf.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_armhf.deb"
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4.9_armhf.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4.9_armhf.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.9_armhf.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-transport-https_1.4.9_i386.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_i386.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_i386.deb"
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4.9_i386.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4.9_i386.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.9_i386.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-transport-https_1.4.9_mips64el.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_mips64el.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_mips64el.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4.9_mips64el.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4.9_mips64el.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.9_mips64el.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-transport-https_1.4.9_mips.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_mips.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_mips.deb"
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4.9_mips.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4.9_mips.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.9_mips.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-transport-https_1.4.9_mipsel.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_mipsel.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_mipsel.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4.9_mipsel.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4.9_mipsel.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.9_mipsel.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-transport-https_1.4.9_ppc64el.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_ppc64el.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_ppc64el.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4.9_ppc64el.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4.9_ppc64el.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.9_ppc64el.deb
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/apt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/apt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4371"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apt packages.

For the stable distribution (stretch), this problem has been fixed in
version 1.4.9.

Specific upgrade instructions :

If upgrading using APT without redirect is not possible in your
situation, you can manually download the files (using wget/curl) for
your architecture using the URL provided below, verifying that the
hashes match. Then you can install them using dpkg -i.

Source archives :

 http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9.dsc
 Size/SHA256 checksum: 2549
 986d98b00caac809341f65acb3d14321d645ce8e87e411c26c66bf149a10dfea
 http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9.tar.xz
 Size/SHA256 checksum: 2079572
 d4d65e7c84da86f3e6dcc933bba46a08db429c9d933b667c864f5c0e880bac0d

Architecture independent files :

 http://security.debian.org/pool/updates/main/a/apt/apt-doc_1.4.9_all.
 deb Size/SHA256 checksum: 365094
 8880640591f64ab7b798f0421d18cba618512ca61ed7c44fbbbb6140423551d5
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-doc_1.4
 .9_all.deb Size/SHA256 checksum: 1004234
 42f4c5945c4c471c3985db1cec7adcac516cc21a497a438f3ea0a2bfa7ffe036

amd64 architecture :

 http://security.debian.org/pool/updates/main/a/apt/apt-transport-http
 s_1.4.9_amd64.deb Size/SHA256 checksum: 170820
 c8c4366d1912ff8223615891397a78b44f313b0a2f15a970a82abe48460490cb
 http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_am
 d64.deb Size/SHA256 checksum: 409958
 fb227d1c4615197a6263e7312851ac3601d946221cfd85f20427a15ab9658d15
 http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_amd64.de
 b Size/SHA256 checksum: 1231594
 dddf4ff686845b82c6c778a70f1f607d0bb9f8aa43f2fb7983db4ff1a55f5fae
 http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4
 .9_amd64.deb Size/SHA256 checksum: 192382
 a099c57d20b3e55d224433b7a1ee972f6fdb79911322882d6e6f6a383862a57d
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4
 .9_amd64.deb Size/SHA256 checksum: 235220
 cfb0a03ecd22aba066d97e75d4d00d791c7a3aceb2e5ec4fbee7176389717404
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.
 9_amd64.deb Size/SHA256 checksum: 916448
 03281e3d1382826d5989c12c77a9b27f5f752b0f6aa28b524a2df193f7296e0b

arm64 architecture :

 http://security.debian.org/pool/updates/main/a/apt/apt-transport-http
 s_1.4.9_arm64.deb Size/SHA256 checksum: 167674
 6635e174290f89555a2eb9cbc083b1fa566b2cd65318212c8c760b87bfb2c544
 http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_ar
 m64.deb Size/SHA256 checksum: 401136
 f7e95f4fbc94409ff4dceb16626beb6cd0eecff5e6982e1bf808af014ea7331f
 http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_arm64.de
 b Size/SHA256 checksum: 1202864
 54abf458ed6b78f56638771fa30cdc9e482469cc0e2dfc2146b3606ea22a3449
 http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4
 .9_arm64.deb Size/SHA256 checksum: 191188
 27d1254e03a80f77458e2c2aceb097c9a85e9cefb4623643a1e25b45e0b889ae
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4
 .9_arm64.deb Size/SHA256 checksum: 235220
 3f046e34009db988edd4e0474b13100ba92adf3beac16456785ee16940b51f2d
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.
 9_arm64.deb Size/SHA256 checksum: 855612
 c3b333927f340bb044ec44f2bfe2abced35ebb3e91457ae91249d26058e7b796

armel architecture :

 http://security.debian.org/pool/updates/main/a/apt/apt-transport-http
 s_1.4.9_armel.deb Size/SHA256 checksum: 165820
 179bcd2457beb0c8449101684c40dc94c9882166b17d584162109928d124cffc
 http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_ar
 mel.deb Size/SHA256 checksum: 394280
 90f760e7480582bcabc2a2f50a44a2d1f5ce4070370295832bc82424887e5289
 http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_armel.de
 b Size/SHA256 checksum: 1190316
 862ba546c54b66732d2a2d17b44aa4d20109f2bd4ba158d62d158ba190eed649
 http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4
 .9_armel.deb Size/SHA256 checksum: 189878
 531e3a673d24b3ae79babc5110d3b27cdbd7a274c0839ff650d691d88d28d8d7
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4
 .9_armel.deb Size/SHA256 checksum: 235218
 46ecb77704fb8957505d96bdfa7c1f190559914ad96297a6b15609ed1a1a24d9
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.
 9_armel.deb Size/SHA256 checksum: 829040
 6d2ca52d1823ca3100a2bc3d98ed15aca5af1b59203006794b8e8cb4575433b0

armhf architecture :

 http://security.debian.org/pool/updates/main/a/apt/apt-transport-http
 s_1.4.9_armhf.deb Size/SHA256 checksum: 166962
 523bf76fd9ee262b08fb04ce2afcd5c0d4e81087c111f31179f5ec2882bbbe93
 http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_ar
 mhf.deb Size/SHA256 checksum: 397912
 4d4699621974098a2d7d1d76c4ee5995e0a56c40a336bbc008308f799cc6bc77
 http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_armhf.de
 b Size/SHA256 checksum: 1198550
 0d2b46b839041ac660a33bb17477e66a5317690135346a9a616dfb2efc07906d
 http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4
 .9_armhf.deb Size/SHA256 checksum: 189906
 37acb514874d95cd39991ff0c759bf17ba2d7f1af746b5e0767b1ee2da52f892
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4
 .9_armhf.deb Size/SHA256 checksum: 235220
 2596fbe7bbad28d57374a2ab6278e9be7cb01e0eee4733f66b76a62492db46e8
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.
 9_armhf.deb Size/SHA256 checksum: 851386
 a7619b4cf5b6205bae21cd25fcc8a856dc108e9f1be6c48e246379f157dc8703

i386 architecture :

 http://security.debian.org/pool/updates/main/a/apt/apt-transport-http
 s_1.4.9_i386.deb Size/SHA256 checksum: 174508
 1e7a22d8f976f56ace375e7e02e19b2629a68e6e28c71d9b9126aa0ac3d3175c
 http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_i3
 86.deb Size/SHA256 checksum: 421244
 25835d5ae4330608421ac4cc6e5c938d36590b55f88bae8ba49b8ce95f3edee1
 http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_i386.deb
 Size/SHA256 checksum: 1263876
 e5ce4790d6565634199199f6bf1d29986468603748aa56d135067ae878416649
 http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4
 .9_i386.deb Size/SHA256 checksum: 194534
 5937ffef18ef22271a616d32388b50a06ee0ce6ccab90ca870548b9aa5b29e32
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4
 .9_i386.deb Size/SHA256 checksum: 235220
 0b045d17a2b45aa59b55c6c5ccd47f738e2edeb189cd892d710f0e35b4d09b27
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.
 9_i386.deb Size/SHA256 checksum: 989166
 16e6470005d25741a9bf39c02ba3f287fda0a66dda8a5859c0efa24a97f56351

mips64el architecture :

 http://security.debian.org/pool/updates/main/a/apt/apt-transport-http
 s_1.4.9_mips64el.deb Size/SHA256 checksum: 168898
 c3af79ed48010edb558d1e80b1a6ee182c66e234506de96c056844743234c9ba
 http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_mi
 ps64el.deb Size/SHA256 checksum: 407486
 d634b98ae56c7d4e8640fbdb515a17a53d86a3f53a1890edbc40085fa2e6b1be
 http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_mips64el
 .deb Size/SHA256 checksum: 1212204
 d9d44ffb8b1860071908267ebda728e8d1086fc911eb66e16f52de07547af6da
 http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4
 .9_mips64el.deb Size/SHA256 checksum: 192760
 6d3fc127c587cce8de194ea7976e3c2664515f5c7959428d89c0d01affcf8567
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4
 .9_mips64el.deb Size/SHA256 checksum: 235226
 30b6ae87ecb434fb008760d2ccd29c2f70cbd44a130eb4731b040d8893dfc909
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.
 9_mips64el.deb Size/SHA256 checksum: 850490
 51e697b30b4f9f5ff0d942e04fb48962e6ae9a898d6bd165d16733c064325fd8

mips architecture :

 http://security.debian.org/pool/updates/main/a/apt/apt-transport-http
 s_1.4.9_mips.deb Size/SHA256 checksum: 169328
 4e9b54777d8c2a5813fa8e4aa395a91b587edd33f4ef661898ada4cbc8943197
 http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_mi
 ps.deb Size/SHA256 checksum: 408388
 8a834ddee8e6182de5768e12564137eb063bee6b1918d4c08c88b9c11a4cb856
 http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_mips.deb
 Size/SHA256 checksum: 1212756
 ea41a5c84b953bb818a6779a141efdcd3e2b46c895eb64e9c0e11d49755bf256
 http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4
 .9_mips.deb Size/SHA256 checksum: 192556
 2e09a9207914f215686a6b305a0e46bbdeb46c18ba9ea9115631ed216a2896cb
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4
 .9_mips.deb Size/SHA256 checksum: 235216
 2c582528fb38966de60476e2121037a80d3357fd95cc8e1453c3e5a52d030655
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.
 9_mips.deb Size/SHA256 checksum: 858768
 125dcd2c1e284600a94a5a471a96534c03e55c9c3091ad06b8d5bfef4d65a574

mipsel architecture :

 http://security.debian.org/pool/updates/main/a/apt/apt-transport-http
 s_1.4.9_mipsel.deb Size/SHA256 checksum: 169958
 cea079260b61817bb6163c3268e6714e09326777d8bbc2b70de7bc6f8cf9ef33
 http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_mi
 psel.deb Size/SHA256 checksum: 409708
 5f95e0433899d05bceb8150a02ee444cc42476a0c81eb35ed43402a0f4f7f5fd
 http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_mipsel.d
 eb Size/SHA256 checksum: 1218954
 6eaf9b8d9e0239d2ffcce046892bf0d0553688dfd5e44332c0dbe84a66648545
 http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4
 .9_mipsel.deb Size/SHA256 checksum: 192822
 59c2dcfe8e23f63cd201777a11b45d5833045ada44b616ed059d223cee99311a
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4
 .9_mipsel.deb Size/SHA256 checksum: 235216
 7fe6c1f8074bff4a29a2988556295ef558b5650edd66145866957e2528c92f7e
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.
 9_mipsel.deb Size/SHA256 checksum: 869792
 2abb3afa5689f3dd0461b998449934ce06ced68ef6cdc8e4e121196f40bd30e6

ppc64el architecture :

 http://security.debian.org/pool/updates/main/a/apt/apt-transport-http
 s_1.4.9_ppc64el.deb Size/SHA256 checksum: 169566
 9de5b780e0e0d381bb1f1cfbff5626e36bae7df6ca25f6c49affc650b88cd152
 http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_pp
 c64el.deb Size/SHA256 checksum: 406494
 5f66c194b5897c490212c15806821d6f924c1353b5031a11383f3b2ebb25d44c
 http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_ppc64el.
 deb Size/SHA256 checksum: 1221036
 b6235daa430bd3e6df37855fd8fcebe057c187335c9e45744e35694600475495
 http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4
 .9_ppc64el.deb Size/SHA256 checksum: 192604
 92d4290b343ada2eaca425f09d56d2767b0bca5221957477515fdb9391497fa8
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4
 .9_ppc64el.deb Size/SHA256 checksum: 235222
 e6ef81e5f61383584aba546056f43458cd83d1d56a96087301ba0454efdd3941
 http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.
 9_ppc64el.deb Size/SHA256 checksum: 888440
 0f2987f64499f3b3f15f2d560d2d41ddc71986e557e94a20ea02af4c71481b47"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

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
if (deb_check(release:"9.0", prefix:"apt", reference:"1.4.9")) flag++;
if (deb_check(release:"9.0", prefix:"apt-doc", reference:"1.4.9")) flag++;
if (deb_check(release:"9.0", prefix:"apt-transport-https", reference:"1.4.9")) flag++;
if (deb_check(release:"9.0", prefix:"apt-utils", reference:"1.4.9")) flag++;
if (deb_check(release:"9.0", prefix:"libapt-inst2.0", reference:"1.4.9")) flag++;
if (deb_check(release:"9.0", prefix:"libapt-pkg-dev", reference:"1.4.9")) flag++;
if (deb_check(release:"9.0", prefix:"libapt-pkg-doc", reference:"1.4.9")) flag++;
if (deb_check(release:"9.0", prefix:"libapt-pkg5.0", reference:"1.4.9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
