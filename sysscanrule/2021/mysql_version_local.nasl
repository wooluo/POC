#
# 
#

include("compat.inc");

if (description)
{
  script_id(129468);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/10");

  script_name(english:"MySQL Server Installed (Linux)");
  script_summary(english:"Checks for MySQL Server on Linux");

  script_set_attribute(attribute:"synopsis", value:
"MySQL Server is installed on the remote Linux host.");
  script_set_attribute(attribute:"description", value:
"MySQL Server is installed on the remote Linux host.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");

  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");
  script_require_ports("Host/RedHat/release", "Host/CentOS/release", "Host/Debian/release", "Host/Ubuntu/release");

  exit(0);
}

include("global_settings.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Determine OS and installed packages

oses = [ "CentOS", "Debian", "RedHat", "Ubuntu" ];
release = packages = regex = NULL;
cpe='cpe:/a:mysql:mysql';

foreach os (oses)
{
  release = get_kb_item("Host/" + os + "/release");
  # Supported OS detected
  if (!empty_or_null(release))
  {
    # Get package list
    if (os == "Debian" || os == "Ubuntu")
    {
      packages = get_kb_item("Host/Debian/dpkg-l");
      regex = "^ii +(mysql-server-core-[0-9\\.]+ +([0-9\\.]+-[0-9][\+]?[a-z]+[0-9\\.].*? ).*)$";
    }
    else
    {
      #see link for package names, looking for Database server and related tools
      #https://dev.mysql.com/doc/refman/8.0/en/linux-installation-rpm.html
      packages = get_kb_item("Host/" + os + "/rpm-list");
      regex = "^(mysql-(community|commercial)-server-([0-9\\.]+-?[0-9])[^\|]+).*$";
    }

    if (empty_or_null(packages)) audit(AUDIT_PACKAGE_LIST_MISSING);
    break;
  }
}

if (empty_or_null(release))
  audit(AUDIT_OS_NOT, join(oses, sep:" / "));


# Determine if MySql Server is installed and attempt to get version
app = 'MySQL Server';
installed = FALSE;

matches = pgrep(pattern:regex, string:packages);
if (empty_or_null(matches)) audit(AUDIT_PACKAGE_NOT_INSTALLED, app);


foreach package (split(matches, sep:'\n'))
{
  matches = pregmatch(pattern:regex, string:package);
  if (empty_or_null(matches)) continue;
  
  extra = {};
  extra["Package"] = matches[1];

  version = UNKNOWN_VER;
  if (os == "Debian" || os == "Ubuntu")
  {
    if (!empty_or_null(matches[2]))
      version = matches[2];
  }
  else #for rpm, there is distinction between commercial and community so the version is in the 3rd block
  {  
    if (!empty_or_null(matches[3]))
      version = matches[3];
  }
  register_install(
    app_name : app,
    path     : '/usr/sbin/mysqld',
    version  : version,
    extra_no_report:make_array( 'Detection', 'Local'),
    cpe      : cpe
  );

  installed = TRUE;
}

if (!installed) audit(AUDIT_PACKAGE_NOT_INSTALLED, app);

report_installs(app_name:app);