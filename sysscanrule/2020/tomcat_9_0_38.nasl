##
# 
##

include('compat.inc');

if (description)
{
  script_id(141446);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/16");

  script_cve_id("CVE-2020-13943");
  script_xref(name:"IAVA", value:"2020-A-0465");

  script_name(english:"Apache Tomcat 8.5.x < 8.5.58 / 9.0.x < 9.0.38 HTTP/2 Request Mix-Up");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is 8.5.x prior to 8.5.58 or 9.0.x prior to 9.0.38. It is, therefore,
affected by a vulnerability. If an HTTP/2 client exceeds the agreed maximum number of concurrent streams for a
connection (in violation of the HTTP/2 protocol), it is possible that a subsequent request made on that connection could
contain HTTP headers - including HTTP/2 pseudo headers - from a previous request rather than the intended headers. This
can lead to users seeing responses for unexpected resources.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/55911430df13f8c9998fbdee1f9716994d2db59b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0656cf04");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.38
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?771617a1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.58, 9.0.38 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13943");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(
  fixed:make_list("8.5.58", "9.0.38"),
  severity:SECURITY_WARNING,
  granularity_regex:"^(8(\.5)?|9(\.0)?)$"
);

