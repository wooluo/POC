##
# 
##

include('compat.inc');

if (description)
{
  script_id(147163);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id("CVE-2021-25329");
  script_xref(name:"IAVA", value:"2021-A-0114");

  script_name(english:"Apache Tomcat 7.0.0 < 7.0.108 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a remote code execution vulnerability");
  script_set_attribute(attribute:"description", value:
"The fix for CVE-2020-9484 was incomplete. The version of Tomcat installed on the remote host is prior to 7.0.108. 
It is, therefore, affected by a remote code execution vulnerability via deserialization. An attacker is able to control the contents and 
name of a file on the server; and b) the server is configured to use the PersistenceManager with a FileStore; and 
c) the PersistenceManager is configured with sessionAttributeValueClassNameFilter=null (the default unless a 
SecurityManager is used) or a sufficiently lax filter to allow the attacker provided object to be deserialized; and 
d) the attacker knows the relative file path from the storage location used by FileStore to the file the attacker has 
control over; then, using a specifically crafted request, the attacker will be able to trigger remote code execution 
via deserialization of the file under their control. Note that both the previously published prerequisites for 
CVE-2020-9484 and the previously published mitigations for CVE-2020-9484 also apply to this issue.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/74b105657ffbd1d1de80455f03446c3bbf30d1f5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5b3746f");
  # https://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.108
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7d039d2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.108 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25329");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(min:'7.0.0', fixed: '7.0.108', severity:SECURITY_WARNING, granularity_regex: "^7(\.0)?$");