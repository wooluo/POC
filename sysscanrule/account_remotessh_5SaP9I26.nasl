include("compat.inc");

if (description)
{
  script_id(102915);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/09/07");

  script_cve_id("CVE-2017-14115");
  script_bugtraq_id(100585);
  script_osvdb_id(164599);

  script_name(english:"Default Password '5SaP9I26' for 'remotessh' Account");
  script_summary(english:"Attempts to log into the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"An administrative account on the remote host uses a known default
password.");
  script_set_attribute(attribute:"description", value:
"The account 'remotessh' on the remote host has the default password '5SaP9I26'.
A remote attacker can exploit this issue to gain administrative access
to the affected system.");
  script_set_attribute(
    attribute:"solution",
    value:"Change the password for this account or disable it."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"see_also", value:"https://www.nomotion.net/blog/sharknatto/");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2017 WebRAY, Inc.");

  script_dependencie("find_service1.nasl", "ssh_detect.nasl", "account_check.nasl");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("ssh_lib.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (! thorough_tests && ! get_kb_item("Settings/test_all_accounts"))
 exit(0, "Neither thorough_tests nor 'Settings/test_all_accounts' is set.");

port = kb_ssh_transport();

session = new("sshlib::session");
session.open_connection(port:port);
ret = session.login(method:"password", extra:{"username":"remotessh", "password":"5SaP9I26"});
session.close_connection();
if(!ret) audit(AUDIT_HOST_NOT, "affected");

session.open_connection(port:port);
ret = session.login(method:"password", extra:{"username":"remotessh", "password":"dec0y"});
session.close_connection();
if(ret) audit(AUDIT_HOST_NOT, "affected");

report="It was possible to login to the remote host using the default credentials of remotessh:5SaP9I26.";
security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
