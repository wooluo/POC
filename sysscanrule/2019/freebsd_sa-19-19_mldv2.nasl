#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128078);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/22 17:10:07");

  script_cve_id("CVE-2019-5608");
  script_xref(name:"IAVA", value:"2019-A-0299");

  script_name(english:"FreeBSD 11.x < 11.2-RELEASE-p13 / 11.x < 11.3-RELEASE-p2 / 12.x < 12.0-RELEASE-p9 MLDv2 Out-of-Bounds Memory Access DoS");
  script_summary(english:"Checks for the version of the FreeBSD kernel.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The version of the FreeBSD kernel running on the remote host is 11.x
prior to 11.2-RELEASE-p13, 11.x prior to 11.3-RELEASE-p2, or 12.x prior
to 12.0-RELEASE-p9. It is, therefore, affected by an out-of-bounds
memory access denial-of-service vulnerability in MLDv2. An
unauthenticated attacker could exploit this, via a malicious MLDv2
listener query packet, to cause an out-of-bounds memory access and a
subsequent kernel panic.

Note: Systems not using IPv6 are not affected.");
  script_set_attribute(attribute:"see_also", value:"https://www.freebsd.org/security/advisories/FreeBSD-SA-19:19.mldv2.asc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate FreeBSD version.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5608");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("freebsd_package.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/FreeBSD/release");
if (!release) audit(AUDIT_OS_NOT, "FreeBSD");

# Patches are available, require paranoid since it is possible
#  to manually patch and have a lower OS level. Additionally,
# systems not using IPv6 are not affected.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = NULL;

if (release =~ "^FreeBSD-11\.[0-2]($|[^0-9])")
  fix = "FreeBSD-11.2_13";
if (release =~ "^FreeBSD-11\.3($|[^0-9])")
  fix = "FreeBSD-11.3_2";
else if (release =~ "^FreeBSD-12\.0($|[^0-9])")
  fix = "FreeBSD-12.0_9";

if (isnull(fix) || pkg_cmp(pkg:release, reference:fix) >= 0)
  audit(AUDIT_HOST_NOT, "affected");

report =
  '\n  Installed version : ' + release +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
