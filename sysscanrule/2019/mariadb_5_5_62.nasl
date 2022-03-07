
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122258);
  script_version("1.1");
  script_cvs_date("Date: 2019/02/19  5:18:33");

  script_cve_id(
    "CVE-2016-9843",
    "CVE-2018-3174",
    "CVE-2018-3282",
    "CVE-2019-2503"
  );
  script_bugtraq_id(
    95131,
    105610,
    105612,
    106626
  );

  script_name(english:"MariaDB 5.5.x < 5.5.62 Multiple Vulnerabilities");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 5.5.x prior to
5.5.62. It is, therefore, affected by multiple denial of service
vulnerabilities.

  - A denial of service vulnerability exists in the crc32_big()
    function within file crc32.c due to an out-of bounds pointer flaw.
    An unauthenticated, remote attacker can exploit this, via a
    specially crafted document, to cause the application to stop
    responding. (CVE-2016-9843)

  - A denial of service  vulnerability exists in the MySQL component
    of Oracle MySQL (subcomponent: Client programs). An authenticated,
    local attacker can exploit this issue, to cause MySQL Server to
    stop responding. (CVE-2018-3174)

  - A denial of service vulnerability exists in the MySQL component of
    Oracle MySQL (subcomponent: Server: Storage Engines). An
    authenticated, remote attacker can exploit this issue, to cause
    MySQL Server to stop responding. (CVE-2018-3282)

  - A denial of service vulnerability exists in the MySQL component of
    Oracle MySQL (subcomponent: Server: Connection Handling). An
    authenticated, adjacent attacker can exploit this, to cause MySQL
    Server to stop responding. (CVE-2019-2503)

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.
");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-5562-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 5.5.62 or later.");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9843");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

variant = 'MariaDB';
minVersion = '5.5';
fixedVersion = '5.5.62-MariaDB';

mysql_check_version(variant:variant, fixed:fixedVersion, min:minVersion, severity:SECURITY_HOLE);
