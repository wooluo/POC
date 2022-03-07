#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123418);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/27 13:52:06");

  script_cve_id(
    "CVE-2019-9894",
    "CVE-2019-9895",
    "CVE-2019-9896",
    "CVE-2019-9897",
    "CVE-2019-9898"
  );
  script_bugtraq_id(
    107484,
    107523
  );

  script_name(english:"PuTTY < 0.71 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PuTTY.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an SSH client that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of PuTTY installed that is prior to
0.71. It is, therefore, affected by multiple vulnerabilities
including:

  - A remotely triggerable buffer overflow in any kind of
    server-to-client forwarding. (CVE-2019-9895)

  - Potential recycling of random numbers used in cryptography.
    (CVE-2019-9898)

  - A remotely triggerable memory overwrite in RSA key exchange can
    occur before host key verification. (CVE-2019-9894)");
  # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-auth-prompt-spoofing.html
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-chm-hijack.html
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-fd-set-overflow.html
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-rng-reuse.html
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-rsa-kex-integer-overflow.html
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-terminal-dos-combining-chars.html
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-terminal-dos-combining-chars-double-width-gtk.html
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-terminal-dos-one-column-cjk.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to PuTTY version 0.71 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9895");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:simon_tatham:putty");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("putty_installed.nasl");
  script_require_keys("installed_sw/PuTTY", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"PuTTY", win_local:TRUE);

constraints = [
  { "fixed_version" : "0.71" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
