#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1220-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(125214);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/16 10:38:53");

  script_cve_id("CVE-2019-3781");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : cf-cli (SUSE-SU-2019:1220-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for cf-cli fixes the following issues :

cf-cli was updated: to version 6.43.0 (bsc#1132242)

Enhancements :

`cf curl` supports a new `--fail` flag (primarily for scripting
purposes) which returns exit code `22` for server errors
[story](https://www.pivotaltracker.com/story/show/130060949)

Improves `cf delete-orphaned-routes` such that it uses a different
endpoint, reducing the chance of a race condition when two users are
simultaneously deleting orphaned routes and associating routes with
applications
[story](https://www.pivotaltracker.com/story/show/163156064)

we've improved the speed of cf services - it now hits a single
endpoint instead of making individual API calls

Security: CVE-2019-3781: CF CLI does not sanitize
user&Atilde;&cent;&Acirc;&#128;&Acirc;&#153;s password in
verbose/trace/debug.

Fixes issue with running cf login in verbose mode whereby passwords
which contains regex were not completely redacted

Fixes issue whilst running commands in verbose mode refresh tokens
were not completely redacted

Other Bug Fixes: Updates help text for cf curlstory

Now refresh tokens work properly whilst using cf curl with V3 CC API
endpoints story

Fixes performance degradation for cf services story

cf delete-service requires that you are targeting a space story

cf enable-service access for a service in an org will succeed if you
have already enabled access for that service in that org story

cf-cli was updated to version 6.42.0 :

Minor Enhancements: updated `cf restage` help text and the first line
in the command's output to indicate that using this command will cause
app downtime
[story](https://www.pivotaltracker.com/story/show/151841382)

updated the `cf bind-route-service` help text to clarify usage
instructions
[story](https://www.pivotaltracker.com/story/show/150111078)

improved an error message for `cf create-service-boker` to be more
helpful when the CC API returns a `502` due to an invalid service
broker catalog

upgraded to Golang 1.11.4
[story](https://www.pivotaltracker.com/story/show/162745359)

added a short name `ue` for `cf unset-env`
[story](https://www.pivotaltracker.com/story/show/161632713)

updated `cf marketplace` command to include a new `broker` column to
prepare for a upcoming services-related feature which will allow
services to have the same name as long as they are associated with
different service brokers
[story](https://www.pivotaltracker.com/story/show/162699756)

Bugs: fix for `cf enable-service-access -p plan` whereby when we
refactored the code in CLI `v6.41.0` it created service plan
visibilities as part of a subsequent run of the command (the
unrefactored code skipped creating the service plan visibilities); now
the command will skip creating service plan visibilities as it did
prior to the refactor
[story](https://www.pivotaltracker.com/story/show/162747373)

updated the `cf rename-buildpack` help text which was missing
reference to the `-s` stack flag
[story](https://www.pivotaltracker.com/story/show/162428661)

updated help text for when users use `brew search cloudfoundry-cli`
[story](https://www.pivotaltracker.com/story/show/161770940)

now when you run `cf service service-instance` for a route service,
the route service url appears in the key value table
[story](https://www.pivotaltracker.com/story/show/162498211)

Update to version 6.41.0 :

Enhancements: updated `cf --help` to include the `delete` command
[story](https://www.pivotaltracker.com/story/show/161556511)

Update to version 6.40.1 :

Bug Fixes: Updates the minimum version for the buildpacks-stacks
association feature. In [CLI
v6.39.0](https://github.com/cloudfoundry/cli/releases/tag/v6.39.0),
when the feature was released, we incorrectly set the minimum to cc
api version as`2.114`. The minimum cc api version is now correctly set
to

[`2.112`](https://github.com/cloudfoundry/capi-release/releases/tag/1.
58.0) .
[story](https://www.pivotaltracker.com/story/show/161464797)Fixes a
bug with inspecting a service instance `cf service service-instance`,
now the `documentation` url displays correctly for services which
populate that field
[story](https://www.pivotaltracker.com/story/show/161251875)

Update to version 6.40.0 :

Bug Fixes: Fix bug where trailing slash on cf api would break listing
commands for older CC APIs story. For older versions of CC API, if the
API URL had a trailing slash, some requests would fail with an
'Unknown request' error. These requests are now handled properly.

Update to version 6.39.0 :

Enhancements: for users on cc api 3.27, cf start is enhanced to
display the new cf app v3 output. For users on cc api 3.27 or lower,
users will see the same v2 output. Note that if you use v3 commands to
create and start your app, if you subsequently use cf stop and cf
start, the routes property in cf app will not populate even though the
route exists story

for users on cc api 3.27, cf restart is enhanced to display the new cf
app v3 output. For users on cc api 3.27 or lower, users will see the
same v2 output. story

for users on cc api 3.27, cf restage is enhanced to display the new cf
app v3 output. For users on cc api 3.27 or lower, users will see the
same v2 output. story

improved help text for -d domains for cf push to include examples of
usage story

cf v3-scale displays additional app information story

if you've created an internal domain, and it is the first domain in
cc, the CLI will now ignore the internal domain and instead choose the
next non-internal domain when you push an app story

Bug Fixes: Fix for users on macOS attempting to brew install cf-cli
the CF CLI using the unreleased master branch of Homebrew story

Fixes an issue whereby, due to a recent cc api change, when you
execute cf push and watch the cf app command, the app display returned
a 400 error story

Fixes a bug whereby if you logged in using client credentials, cf auth
user pass --client credentials you were unable to create an org; now
create-org will assign the role to the user id specified in your
manifest story

fixes an issue introduced when we refactored cf start and as part of
that work, we stopped blocking on the initial connection with the
logging backend; now the CLI blocks until the NOAA connection is made,
or the default dial timeout of five seconds is reached story

update to version 6.38.0 :

Enhancements: v3-ssh process type now defaults to web story

Support added for setting tags for user provided service instances
story

Now a warning appears if you attempt to use deprecated properties and
variable substitution story

Updated usage so now you can rename the cf binary use it with every
command story

cf events now displays the Diego cell_id and instance guid in crash
events story

Includes cf service service-instance table display improvements
wherein the service instance information is now grouped separately
from the binding information story

cf service service-instance table display information for user
provided services changed: status has been added to the table story

Bug Fixes: the CLI now properly handles escaped commas in the
X-Cf-Warnings header

Update to version 6.37.0 :

Enhancements The api/cloudcontroller/ccv2 package has been updated
with more functions #1343

Now a warning appears if you are using a API version older than
2.69.0, which is no longer officially supported

Now the CLI reads the username and password from the environment
variables #1358

Bug Fixes: Fixes bug whereby X-Cf-Warnings were not being unescaped
when displayed to user #1361

When using CF_TRACE=1, passwords are now sanitized #1375 and tracker

Update to version 6.36.0 :

Bug Fixes: int64 support for cf/flags library, #1333

Debian package, #1336

Web action flag not working on CLI 0.6.5, #1337

When a cf push upload fails/Consul is down, a panic occurs, #1340 and
#1351

update to version 6.35.2 :

Bug Fixes: Providing a clearer services authorization warning message
when a service has been disabled for the organization, fixing #1344

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1132242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/cloudfoundry/capi-release/releases/tag/1.58.0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/cloudfoundry/cli/releases/tag/v6.39.0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.pivotaltracker.com/story/show/130060949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.pivotaltracker.com/story/show/150111078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.pivotaltracker.com/story/show/151841382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.pivotaltracker.com/story/show/161251875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.pivotaltracker.com/story/show/161464797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.pivotaltracker.com/story/show/161556511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.pivotaltracker.com/story/show/161632713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.pivotaltracker.com/story/show/161770940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.pivotaltracker.com/story/show/162428661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.pivotaltracker.com/story/show/162498211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.pivotaltracker.com/story/show/162699756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.pivotaltracker.com/story/show/162745359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.pivotaltracker.com/story/show/162747373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.pivotaltracker.com/story/show/163156064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3781/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191220-1/
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for CAP 15:zypper in -t patch
SUSE-SLE-Module-CAP-Tools-15-2019-1220=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cf-cli");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"cf-cli-6.43.0-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"cf-cli-6.43.0-3.3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cf-cli");
}
