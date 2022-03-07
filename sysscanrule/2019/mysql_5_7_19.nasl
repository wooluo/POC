#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101821);
  script_version("1.9");
  script_cvs_date("Date: 2019/07/18 17:19:50");

  script_cve_id(
    "CVE-2017-3529",
    "CVE-2017-3633",
    "CVE-2017-3634",
    "CVE-2017-3635",
    "CVE-2017-3637",
    "CVE-2017-3638",
    "CVE-2017-3639",
    "CVE-2017-3640",
    "CVE-2017-3641",
    "CVE-2017-3642",
    "CVE-2017-3643",
    "CVE-2017-3644",
    "CVE-2017-3645",
    "CVE-2017-3647",
    "CVE-2017-3648",
    "CVE-2017-3649",
    "CVE-2017-3650",
    "CVE-2017-3651",
    "CVE-2017-3652",
    "CVE-2017-3653",
    "CVE-2017-3731",
    "CVE-2017-10279",
    "CVE-2017-10284",
    "CVE-2017-10296",
    "CVE-2017-10365",
    "CVE-2019-2730"
  );
  script_bugtraq_id(
    95813,
    99722,
    99729,
    99730,
    99746,
    99748,
    99753,
    99765,
    99767,
    99772,
    99775,
    99778,
    99779,
    99783,
    99789,
    99796,
    99799,
    99802,
    99805,
    99808,
    99810,
    101316,
    101373,
    101385,
    101429
  );

  script_name(english:"MySQL 5.7.x < 5.7.19 Multiple Vulnerabilities (Jul 2017 CPU) (Oct 2017 CPU) (Jul 2019 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.7.x prior to
5.7.19. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the UDF component that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3529)

  - An unspecified flaw exists in the Memcached component
    that allows an unauthenticated, remote attacker to
    impact integrity and availability. (CVE-2017-3633)

  - Multiple unspecified flaws exist in the DML component
    that allow an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3634,
    CVE-2017-3639, CVE-2017-3640, CVE-2017-3641,
    CVE-2017-3643, CVE-2017-3644, CVE-2017-10296)

  - An unspecified flaw exists in the Connector/C and C API
    components that allow an authenticated, remote attacker
    to cause a denial of service condition. (CVE-2017-3635)

  - An unspecified flaw exists in the X Plugin component
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3637)

  - Multiple unspecified flaws exist in the Optimizer
    component that allow an authenticated, remote attacker
    to cause a denial of service condition. (CVE-2017-3638,
    CVE-2017-3642, CVE-2017-3645, CVE-2017-10279)

  - Multiple unspecified flaws exist in the Replication
    component that allow an authenticated, remote attacker
    to cause a denial of service condition. (CVE-2017-3647,
    CVE-2017-3649)

  - An unspecified flaw exists in the Charsets component
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3648)

  - An unspecified flaw exists in the C API component that
    allows an unauthenticated, remote attacker to disclose
    sensitive information. (CVE-2017-3650)

  - An unspecified flaw exists in the Client mysqldump
    component that allows an authenticated, remote attacker
    to impact integrity. (CVE-2017-3651)

  - Multiple unspecified flaws exist in the DDL component
    that allow an authenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2017-3652,
    CVE-2017-3653)

  - An unspecified flaw exists in the OpenSSL Encryption
    component that allows an unauthenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2017-3731)

  - An unspecified flaw exists in the Stored Procedure
    component that allows an authenticated, remote attacker
    to cause a denial of service condition. (CVE-2017-10284)

  - An unspecified flaw exists in the InnoDB component that
    allows an authenticated, remote attacker to cause a
    denial of service condition or to modify the contents of
    the MySQL database. (CVE-2017-10365)

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-19.html");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html
  script_set_attribute(attribute:"see_also", value:"");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.oracle.com/epmos/faces/DocumentDisplay?id=2279658.1
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2307762.1");
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3809960.xml
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3937099.xml
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.7.19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3633");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.7.19', min:'5.7', severity:SECURITY_WARNING);
