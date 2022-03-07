#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122878);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/18  9:13:26");

  script_name(english:"Linux Alternate Patch Detection");
  script_summary(english:"Calls scripts for checking alternate patching/hotfixing software.");

  script_set_attribute(
    attribute:"synopsis",
    value:"Runs dependency plugins."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This is a wrapper plugin for ensuring that detection scripts for
custom software patching methodologies (outside of yum, dpkg, and
similar package management systems) get run prior to the execution
of localcheck plugins.

Add additional detection scripts to the script_dependencies
attribute."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/18");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"General");

  script_dependencies("ksplice.nasl");

  exit(0);
}

include("global_settings.inc");

exit(0, "Dependency scripts run.");
