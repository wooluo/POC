#
# (C) Webray Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51799292);
  script_version("1.14");
  script_cvs_date("Date: 2018/07/24 18:56:10");

  script_cve_id(
    "CVE-2006-7168",
    "CVE-2015-6831",
    "CVE-2015-4642",
	"CVE-2006-7243",
	"CVE-2007-2728",
	"CVE-2007-3205",
	"CVE-2007-4596",
	"CVE-2009-4418",
	"CVE-2010-3870",
	"CVE-2010-4409",
	"CVE-2010-4657",
	"CVE-2010-4699",
	"CVE-2011-0421",
	"CVE-2011-0708",
	"CVE-2011-0753",
	"CVE-2011-0755",
	"CVE-2011-1092",
	"CVE-2011-1148",
	"CVE-2011-1153",
	"CVE-2011-1398",
	"CVE-2011-1464",
	"CVE-2011-1466",
	"CVE-2011-1467",
	"CVE-2011-1468",
	"CVE-2011-1469",
	"CVE-2011-1470",
	"CVE-2011-1471",
	"CVE-2011-1939",
	"CVE-2011-2202",
	"CVE-2011-2483",
	"CVE-2011-3182",
	"CVE-2011-3267",
	"CVE-2011-3268",
	"CVE-2011-4718",
	"CVE-2011-4885",
	"CVE-2012-0057",
	"CVE-2012-0788",
	"CVE-2012-0789",
	"CVE-2012-0831",
	"CVE-2012-1171",
	"CVE-2012-1172",
	"CVE-2012-1823",
	"CVE-2012-2143",
	"CVE-2012-2311",
	"CVE-2012-2336",
	"CVE-2012-2386",
	"CVE-2012-2688",
	"CVE-2012-3365",
	"CVE-2012-3450",
	"CVE-2013-1635",
	"CVE-2013-1643",
	"CVE-2013-1824",
	"CVE-2013-2110",
	"CVE-2013-4113",
	"CVE-2013-4248",
	"CVE-2013-6420",
	"CVE-2013-6501",
	"CVE-2013-6712",
	"CVE-2013-7327",
	"CVE-2014-0207",
	"CVE-2014-0236",
	"CVE-2014-0237",
	"CVE-2014-0238",
	"CVE-2014-2020",
	"CVE-2014-2497",
	"CVE-2014-3478",
	"CVE-2014-3479",
	"CVE-2014-3480",
	"CVE-2014-3487",
	"CVE-2014-3515",
	"CVE-2014-3587",
	"CVE-2014-3597",
	"CVE-2014-3668",
	"CVE-2014-3669",
	"CVE-2014-3670",
	"CVE-2014-3981",
	"CVE-2014-4049",
	"CVE-2014-4670",
	"CVE-2014-4698",
	"CVE-2014-4721",
	"CVE-2014-5459",
	"CVE-2014-8142",
	"CVE-2014-9425",
	"CVE-2014-9426",
	"CVE-2014-9427",
	"CVE-2014-9652",
	"CVE-2014-9653",
	"CVE-2014-9705",
	"CVE-2014-9767",
	"CVE-2014-9912",
	"CVE-2015-0231",
	"CVE-2015-0232",
	"CVE-2015-0273",
	"CVE-2015-1351",
	"CVE-2015-1352",
	"CVE-2015-2331",
	"CVE-2015-2348",
	"CVE-2015-2783",
	"CVE-2015-2787",
	"CVE-2015-3307",
	"CVE-2015-3329",
	"CVE-2015-3330",
	"CVE-2015-3411",
	"CVE-2015-3412",
	"CVE-2015-4021",
	"CVE-2015-4022",
	"CVE-2015-4024",
	"CVE-2015-4025",
	"CVE-2015-4026",
	"CVE-2015-4116",
	"CVE-2015-4147",
	"CVE-2015-4148",
	"CVE-2015-4598",
	"CVE-2015-4599",
	"CVE-2015-4600",
	"CVE-2015-4601",
	"CVE-2015-4602",
	"CVE-2015-4603",
	"CVE-2015-4604",
	"CVE-2015-4605",
	"CVE-2015-4643",
	"CVE-2015-4644",
	"CVE-2015-5589",
	"CVE-2015-5590",
	"CVE-2015-6832",
	"CVE-2015-6833",
	"CVE-2015-6834",
	"CVE-2015-6835",
	"CVE-2015-6836",
	"CVE-2015-7803",
	"CVE-2015-7804",
	"CVE-2015-8835",
	"CVE-2015-8838",
	"CVE-2015-8865",
	"CVE-2015-8873",
	"CVE-2015-8874",
	"CVE-2015-8877",
	"CVE-2015-8879",
	"CVE-2015-8880",
	"CVE-2015-8935",
	"CVE-2015-8994",
	"CVE-2015-9253",
	"CVE-2016-10161",
	"CVE-2016-10158",
	"CVE-2016-10159",
	"CVE-2016-10160",
	"CVE-2016-10397",
	"CVE-2016-10712",
	"CVE-2016-1903",
	"CVE-2016-2554",
	"CVE-2016-3078",
	"CVE-2016-3141",
	"CVE-2016-3142",
	"CVE-2016-3185",
	"CVE-2016-4070",
	"CVE-2016-4342",
	"CVE-2016-4343",
	"CVE-2016-4344",
	"CVE-2016-4345",
	"CVE-2016-4346",
	"CVE-2016-4537",
	"CVE-2016-4538",
	"CVE-2016-4539",
	"CVE-2016-4540",
	"CVE-2016-4541",
	"CVE-2016-4542",
	"CVE-2016-4543",
	"CVE-2016-5093",
	"CVE-2016-5094",
	"CVE-2016-5095",
	"CVE-2016-5096",
	"CVE-2016-5114",
	"CVE-2016-5385",
	"CVE-2016-5399",
	"CVE-2016-5768",
	"CVE-2016-5769",
	"CVE-2016-5770",
	"CVE-2016-5771",
	"CVE-2016-5773",
	"CVE-2016-6174",
	"CVE-2016-6288",
	"CVE-2016-6289",
	"CVE-2016-6290",
	"CVE-2016-6291",
	"CVE-2016-6292",
	"CVE-2016-6294",
	"CVE-2016-6295",
	"CVE-2016-6296",
	"CVE-2016-6297",
	"CVE-2016-7124",
	"CVE-2016-7125",
	"CVE-2016-7126",
	"CVE-2016-7127",
	"CVE-2016-7128",
	"CVE-2016-7129",
	"CVE-2016-7130",
	"CVE-2016-7131",
	"CVE-2016-7132",
	"CVE-2016-7411",
	"CVE-2016-7412",
	"CVE-2016-7413",
	"CVE-2016-7414",
	"CVE-2016-7416",
	"CVE-2016-7417",
	"CVE-2016-7418",
	"CVE-2016-7478",
	"CVE-2016-7480",
	"CVE-2016-9137",
	"CVE-2016-9138",
	"CVE-2016-9934",
	"CVE-2016-9935",
	"CVE-2017-11142",
	"CVE-2017-11143",
	"CVE-2017-11144",
	"CVE-2017-11145",
	"CVE-2017-11147",
	"CVE-2017-11628",
	"CVE-2017-12933",
	"CVE-2017-16642",
	"CVE-2017-7272",
	"CVE-2017-7890",
	"CVE-2017-7963",
	"CVE-2017-8923",
	"CVE-2017-9224",
	"CVE-2017-9225",
	"CVE-2017-9226",
	"CVE-2017-9227",
	"CVE-2017-9228",
	"CVE-2017-9229",
	"CVE-2018-10545",
	"CVE-2018-10546",
	"CVE-2018-10547",
	"CVE-2018-10548",
	"CVE-2018-10549",
	"CVE-2018-14851",
	"CVE-2018-14883",
	"CVE-2018-15132",
	"CVE-2018-17082",
	"CVE-2018-19395",
	"CVE-2018-19396",
	"CVE-2018-19520",
	"CVE-2018-19935",
	"CVE-2018-20783",
	"CVE-2018-5711",
	"CVE-2018-5712",
	"CVE-2018-7584",
	"CVE-2019-6977",
	"CVE-2019-9020",
	"CVE-2019-9021",
	"CVE-2019-9023",
	"CVE-2019-9024",
	"CVE-2019-9637",
	"CVE-2019-9638",
	"CVE-2019-9639",
	"CVE-2019-9641");

  script_name(english:"PHP 5.2 <= 5.2.17 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is affected by
multiple flaws."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP 5.2 installed on the
remote host is older than 5.2.17." );

  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_17.php");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.2.17");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.2.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2020 Webray Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

if (version =~ "^5\.2\.([0-9]|1[0-7])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Recommend to upgrade to the latest version.\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
