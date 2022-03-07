#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127052);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/26 14:53:47");

  script_cve_id("CVE-2019-9959");
  script_bugtraq_id(109342);
  script_xref(name: "IAVB", value: "2019-B-0064");

  script_name(english:"Poppler < 0.79 Integer Overflow Vulnerability");
  script_summary(english:"Checks for an installation of poppler.");

  script_set_attribute(attribute:"synopsis", value:
"A package installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Poppler installed on the remote host is 0.79. It is, therefore, affected by 
an integer overflow vulnerability. The JPXStream::init function in Poppler 0.78.0 and earlier doesn't
check for negative values of stream length, leading to an Integer Overflow, thereby making it possible
to allocate a large memory chunk on the heap, with a size controlled by an attacker, as demonstrated by
pdftocairo.

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://gitlab.freedesktop.org/poppler/poppler/blob/master/NEWS
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:"Upgrade to a patched version of Poppler once it is available.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9959");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date",value:"2019/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:freedesktop:poppler");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"agent", value:"macosx");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "macosx_eval_installed.nbin");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

distros = make_list(
  'Host/AIX/lslpp',
  'Host/Gentoo/qpkg-list',
  'Host/HP-UX/swlist',
  'Host/MacOSX/packages',
  'MacOSX/packages/homebrew',
  'Host/McAfeeLinux/rpm-list',
  'Host/Slackware/packages',
  'Host/Solaris/showrev',
  'Host/Solaris11/pkg-list'
);

pkgs_list = make_array();

distro = '';

foreach pkgmgr (distros)
{
  pkgs = get_kb_item(pkgmgr);
  if(pkgmgr=~'^MacOSX') sep = '|';
  else sep = '\n';
  if(!isnull(pkgs) && 'poppler' >< pkgs)
  {
    distro = pkgmgr;
    foreach pkg (split(pkgs,sep:sep,keep:FALSE))
    {
      match = pregmatch(pattern:"(?:lib\d*|gir1.2-|\s|^)poppler\d*(?:-?(?:glib[^-]{0,2}|qt[^-]{0,2}|utils|dbg|dbgsym|debuginfo|private|devel|cpp[^-]{0,2}|gir[^-]+|dev|-0\.18|<|-\d|.x86-64)+)*(?:-|\s*)(\d+(?:\.\d+){1,2}(?:-[0-9]+)?)[^\n]*", string:pkg);
      if(!empty_or_null(match) && !empty_or_null(match[1]))
      {
        if("-" >< match[1])
          pkgs_list[pkg] = str_replace(string: match[1], find:'-', replace:'.');
        else pkgs_list[pkg] = match[1];
      }
    }
  }
}

flag = 0;
vulnerable_pkgs = '';

if(!empty_or_null(pkgs_list))
{
  foreach pkg (keys(pkgs_list))
  {
    ver = pkgs_list[pkg];
    if ((empty_or_null(ver)) || (ver !~ "(?!^.*\.\..*$)^[0-9][0-9.]+?$")) continue;
    if(
      distro =~ "(Solaris|Solaris11|Gentoo|BSD|Slackware|HP-UX|AIX|McAfeeLinux|MacOSX)" &&
      ver_compare(ver:ver, fix:'0.78', strict:FALSE) <= 0
    )
    {
      vulnerable_pkgs += '  ' + pkg + '\n';
      flag++;
    }
  }
}
else audit(AUDIT_NOT_INST, 'poppler');

if(flag > 0)
{
  report = '\nThe following packages are associated with a vulnerable version of poppler : \n\n';
  report += vulnerable_pkgs;
  report += '\nFix : Upgrade poppler to a fixed release.\n';
  security_report_v4(severity:SECURITY_WARNING, extra:report, port:0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'poppler');
