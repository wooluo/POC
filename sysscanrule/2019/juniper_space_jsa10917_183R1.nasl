#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121067);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/02 21:54:17");

  script_cve_id(
    "CVE-2017-13672",
    "CVE-2018-10675",
    "CVE-2018-10872",
    "CVE-2018-3639",
    "CVE-2018-3665",
    "CVE-2018-5683",
    "CVE-2018-7858",
    "CVE-2019-0016",
    "CVE-2019-0017"
  );

  script_name(english:"Juniper Junos Space < 18.3R1 Multiple Vulnerabilities (JSA10917)");
  script_summary(english:"Checks the version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos Space
version is prior to 18.3R1. It is, therefore, affected by multiple
vulnerabilities:

  - A use after free vulnerability exists in the
   do_get_mempolicy function. An local attacker can exploit
   this to cause a denial of service condition.
   (CVE-2018-10675)

  - A malicious authenticated user may be able to delete a
    device from the Junos Space database without the
    privileges through crafted Ajax interactions from
    another legitimate delete action performed by an
    administrative user. (CVE-2019-0016)

  - A flaw in validity checking of image files uploaded
    to Junos Space could allow an attacker to upload
    malicious scripts or images. (CVE-2019-0017)

Additionally, Junos Space is affected by several other
vulnerabilities exist as noted in the vendor advisory.

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.
");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10917");
  script_set_attribute(attribute:"solution", value:"Upgrade to Junos Space 18.3R1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10675");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Junos_Space/version");

  exit(0);
}

include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Junos_Space/version');

check_junos_space(ver:ver, fix:'18.3R1', severity:SECURITY_HOLE);
