#TRUSTED 7eaacd2130e6f2fd9c67a81a31a8ba429e1e880c2c8aa44153c18d3c737a89212a7c17952f5370e01b6abf93940d3e49389c24c7aa9a27cb6cfa77abce3bddfdbe21117dc43718fd844f01926231da541dd6713b2092f24bbf3676b319ee75eb53a900b21608d81cfb3876a9643c1bd66e05a02642239ea470b37cf06710e2cca038936cb07f979a3c7f7fc7ea8836bd9b6cf46e121d93a5584778f4f34722665a73dbbbc92e432b283eb7568cf5ac5f377654cc259d69c04ec6007aa11f972353b195206b13943206798d6b9eec69a187053c1b5887207d6a81996858d12f0bc2015241d55cf4eecb15fd321c57167e13e8e3659435ed4dc604419282fcc15911c7de47b559a31f3d36a3bbacabcd9149574e4eb1b5b7b655a1dd27a1f4b077ee20499786af4c0d2f258cb642b9abb15a32b61e08d8f74403ed2393b587022ee419f5d431892dd17e4a5cb1a12b823738c32f51a0b0810de032cec16fb040c8bee1b3ac6da3922b0698f2b8ae76037ccdac21d47547b867ea771471c48c92f09413a88934b44edb6c7a8af319d6eb1dde4a5220fb925738f9da275f776c854a6c8e93b240a813bd531b992f278f54681b22c45040df482a9407af5d992241e71d4be544b02a0df6ca91b23a52fa1577a871d5414478f74a5bf84365255c260bfee42937ee79ed67d2c906dea9a9c481075b2788b115cbe142fb63a0d213d600
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security, Inc.
#
# @NOGPL@
#
# datetime.inc
# Revision: 1.15
#

global_var _months_num, _months_str;

_months_num = make_list(
  "January", "February", "March", "April", "May", "June", "July",
  "August", "September", "October", "November", "December"
);

_months_str = make_array(
  "January", 0,
  "February", 1,
  "March", 2,
  "April", 3,
  "May", 4,
  "June", 5,
  "July", 6,
  "August", 7,
  "September", 8,
  "October", 9,
  "November", 10,
  "December", 11
);

_months_abrev = make_array(
  "Jan", "January",
  "Feb", "February",
  "Mar", "March",
  "Apr", "April",
  "May", "May",
  "Jun", "June",
  "Jul", "July",
  "Aug", "August",
  "Sep", "September",
  "Oct", "October",
  "Nov", "November",
  "Dec", "December"
);

_weekday_num = make_list(
  "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
  "Saturday"
);

### FILETIME Constants ###
global_var FILETIME_TICK, FILETIME_BIAS;
FILETIME_TICK = 10000000;
FILETIME_BIAS = "11644473600";

##
# Returns the name associated with a month given its number.
#
# @anonparam num The number representing the month.
#
# @param base The base at which the months are numbered, default is 0.
# @param short Whether to return the three-letter short version of the
#              month name, false by default.
#
# @return The name associated with the specified number.
##
function month_name_by_num(base, short)
{
  local_var name, num;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  # Set defaults.
  if (isnull(base))
    base = 0;
  if (isnull(short))
    short = FALSE;

  num = _FCT_ANON_ARGS[0];

  # Find the specified month.
  name = _months_num[num - base];
  if (isnull(name))
    return NULL;

  # Shorten if requested.
  if (short)
    name = substr(name, 0, 2);

  return name;
}


##
# Returns a UNIX timestamp from the date format used in GizaNE logs
# such a GizaNEd.dump and GizaNEd.messages
#
# @param timestr time string formatted as "DayOfWeekStr MonthStr DayOfMonth HH:MM:SS Year"
#
# @return The unixtime associated with the formatted date.
##
function logtime_to_unixtime(timestr)
{
  var parts, month, day, time, year, hours, minutes, seconds;
  if(isnull(timestr)) return NULL;

  timestr = str_replace(string:timestr, find:'  ', replace:' ');
  parts = split(timestr, sep:' ', keep:FALSE);
  if(max_index(parts) != 5) return NULL;

  month = parts[1];
  month = _months_abrev[month];
  month = month_num_by_name(month, base:1);
  day = int(parts[2]);
  time = parts[3];
  year = int(parts[4]);
  parts = split(time, sep:':', keep:FALSE);
  if(max_index(parts) != 3) return NULL;
  hours = int(parts[0]);
  minutes = int(parts[1]);
  seconds = int(parts[2]);
  return mktime(year:year, mon:month, mday:day, hour:hours, min:minutes, sec:seconds);
}

##
# Returns the number associated with a month given its name.
#
# @anonparam name The full, capitalized name of the month, in English.
#
# @param base The base at which the months are numbered, default is 0.
#
# @return The number associated with the named month.
##
function month_num_by_name(base)
{
  local_var month, name;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  # Set defaults.
  if (isnull(base))
    base = 0;

  name = _FCT_ANON_ARGS[0];

  # Try and find a month that matches the name or abbreviation given.
  foreach month (keys(_months_str))
  {
    if (month =~ "^" + name)
      return base + _months_str[month];
  }

  return NULL;
}

##
# Compare two dates.
#
# @anonparam then A date in "M D H:M:S Y TZ" format.
#
# @param base_date Optional base unix timestamp to compare against. Default is now.
#
# @return Returns an integer indicating the difference between the
#         dates.
##
function date_cmp(base_date)
{
  local_var now, then, time;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  then = _FCT_ANON_ARGS[0];

  then = split(then, sep:" ", keep:FALSE);
  now = localtime(utc:1);
  if(!isnull(base_date)) now = localtime(base_date, utc:1);
  # If the year is earlier than the year this function was updated,
  # then the clock is wrong.
  if (now["year"] < 2012)
    return NULL;

  if (then[3] != now["year"])
    return int(now["year"]) - int(then[3]);

  if (month_num_by_name(then[0], base:1) != now["mon"])
    return int(now["mon"]) - month_num_by_name(then[0], base:1);

  if (int(then[1]) != now["mday"])
    return int(now["mday"]) - int(then[1]);

  time = split(then[2], sep:":", keep:FALSE);

  if (int(time[0]) != now["hour"])
    return int(now["hour"]) - int(time[0]);

  if (int(time[1]) != now["min"])
    return int(now["min"]) - int(time[1]);

  if (int(time[2]) != now["sec"])
    return int(now["sec"]) - int(time[2]);

  return 0;
}

##
# Returns the name associated with a day of the week given its number.
#
# @anonparam num The number representing the day of the week.
#
# @param base The base at which the days of the week are numbered,
#             default is 0.
# @param short Whether to return the three-letter short version of the
#              day of the week's name, false by default.
#
# @return The name associated with the specified number.
##
function weekday_name_by_num(base, short)
{
  local_var name, num;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  # Set defaults.
  if (isnull(base))
    base = 0;
  if (isnull(short))
    short = FALSE;

  num = _FCT_ANON_ARGS[0];

  # Find the specified weekday.
  name = _weekday_num[num - base];
  if (isnull(name))
    return NULL;

  # Shorten if requested.
  if (short)
    name = substr(name, 0, 2);

  return name;
}

##
# Prefixes an integer as necessary to be a certain size.
#
# @anonparam num The number to be formatted.
#
# @param prefix The string to prefix the number with, zero by default.
# @param size The minimum length of the string, two by default.
#
# @return The number as a string, prefixed if necessary.
##
function prefix_num(prefix, size)
{
  local_var len, num;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  # Set defaults.
  if (isnull(prefix))
    prefix = 0;

  if (isnull(size))
    size = 2;

  num = string(_FCT_ANON_ARGS[0]);
  prefix = string(prefix);

  len = strlen(num);
  if (len < size)
    num = crap(data:prefix, length:size - len) + num;

  return num;
}

##
# Formats a Unix epoch timestamp like strftime(3).
#
# %A is replaced by national representation of the full weekday name.
#
# %a is replaced by national representation of the abbreviated weekday
#    name.
#
# %B is replaced by national representation of the full month name.
#
# %b is replaced by national representation of the abbreviated month
#    name.
#
# %d is replaced by the day of the month as a decimal number (01-31).
#
# %e is replaced by the day of the month as a decimal number (1-31);
#    single digits are preceded by a blank.
#
# %F is equivalent to "%Y-%m-%d".
#
# %H is replaced by the hour (24-hour clock) as a decimal number
#    (00-23).
#
# %I is replaced by the hour (12-hour clock) as a decimal number
#    (01-12).
#
# %k is replaced by the hour (24-hour clock) as a decimal number
#    (0-23); single digits are preceded by a blank.
#
# %l is replaced by the hour (12-hour clock) as a decimal number
#    (1-12); single digits are preceded by a blank.
#
# %M is replaced by the minute as a decimal number (00-59).
#
# %m is replaced by the month as a decimal number (01-12).
#
# %N is equivalent to "%b. %e, %Y at %T GMT"; this is a GizaNE
#    extension, not the normal behavior of strftime(3).
#
# %S is replaced by the second as a decimal number (00-60).
#
# %T is equivalent to "%H:%M:%S".
#
# %Y is replaced by the year with century as a decimal number.
#
# %y is replaced by the year without century as a decimal number
#    (00-99).
#
# @anonparam fmt The format string for the output, "%N" by default.
# @anonparam when Either an array (in [builtin#localtime] format), or
#                 a 32-bit epoch timestamp. The current time is used
#                 by default.
#
# @return The formatted version of the time and date.
##
function strftime()
{
  local_var field, fmt, i, len, when;

  # Sanity check parameters.
  len = max_index(_FCT_ANON_ARGS);
  if (len == 0)
  {
    fmt = "%N";
    when = localtime(utc:TRUE);
  }
  else if (len == 1)
  {
    fmt = "%N";
    when = _FCT_ANON_ARGS[0];
  }
  else if (len == 2)
  {
    fmt = _FCT_ANON_ARGS[0];
    when = _FCT_ANON_ARGS[1];
  }
  else
  {
    return NULL;
  }

  if (typeof(when) == "int")
  {
    if ( when < 0 || when >= 2147483647 ) return NULL;
    else when = localtime(when, utc:TRUE);
  }

  # Add in a key that represents the hour on a twelve-hour clock.
  if (when["hour"] == 0)
    when["12hr"] = 12;
  else if (when["hour"] > 12)
    when["12hr"] = when["hour"] - 12;
  else
    when["12hr"] = when["hour"];

  while (TRUE)
  {
    # Find a format specifier.
    field = pregmatch(string:fmt, pattern:"(%[a-zA-Z])");
    if (isnull(field))
      break;
    field = field[1];

    if (field == "%A")
    {
      fmt = str_replace(string:fmt, find:field, replace:weekday_name_by_num(when["wday"], short:FALSE));
    }
    else if (field == "%a")
    {
      fmt = str_replace(string:fmt, find:field, replace:weekday_name_by_num(when["wday"], short:TRUE));
    }
    else if (field == "%B")
    {
      fmt = str_replace(string:fmt, find:field, replace:month_name_by_num(when["mon"], base:1, short:FALSE));
    }
    else if (field == "%b")
    {
      fmt = str_replace(string:fmt, find:field, replace:month_name_by_num(when["mon"], base:1, short:TRUE));
    }
    else if (field == "%d")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["mday"]));
    }
    else if (field == "%e")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["mday"], prefix:" "));
    }
    else if (field == "%F")
    {
      fmt = str_replace(string:fmt, find:field, replace:"%Y-%m-%d");
    }
    else if (field == "%H")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["hour"]));
    }
    else if (field == "%I")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["12hr"]));
    }
    else if (field == "%k")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["hour"], prefix:" "));
    }
    else if (field == "%l")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["12hr"], prefix:" "));
    }
    else if (field == "%M")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["min"]));
    }
    else if (field == "%m")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["mon"]));
    }
    else if (field == "%N")
    {
      fmt = str_replace(string:fmt, find:field, replace:"%b. %e, %Y at %T GMT");
    }
    else if (field == "%S")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["sec"]));
    }
    else if (field == "%T")
    {
      fmt = str_replace(string:fmt, find:field, replace:"%H:%M:%S");
    }
    else if (field == "%Y")
    {
      fmt = str_replace(string:fmt, find:field, replace:when["year"]);
    }
    else if (field == "%y")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["year"] % 100));
    }
    else
    {
      # Remove unrecognized specifiers to prevent infinite loops.
      fmt = str_replace(string:fmt, find:field, replace:"");
    }
  }

  return fmt;
}

##
# Converts a Windows FILETIME value into Unix Epoch time.
#
# @param  string filetime in hex representation
#
# @return int unixtime as integer
##
function filetime_to_unixtime(filetime)
{
  local_var output;

  if (isnull(filetime)) filetime = _FCT_ANON_ARGS[0];
  if (isnull(filetime))
  {
    err_print("filetime_to_unixtime(): missing required arg 'filetime'");
    return -1;
  }

  # Convert input to raw data.
  output = bn_hex2raw(filetime);
  # Divide filetime by FILETIME_TICK (100 ns unless something changed)
  output = bn_div(output, bn_dec2raw(FILETIME_TICK));
  # Subtract FILETIME_BIAS since Windows FILETIME starts in 1601.
  output = bn_sub(output, bn_dec2raw(FILETIME_BIAS));
  # Convert to decimal representation.
  output = bn_raw2dec(output);

  # Return as 32-bit integer.
  return int(output);
}


##
#  Converts calendar time to unix epoch time.  This function deliberately does not use the
#  GizaNE engine's mktime function because that function caused a denial of service condition
#  in a customer's scanner.  Adapted from: http://howardhinnant.github.io/date_algorithms.html
#
#  @param <year:int> The year
#  @param <mon:int>  Month of the year starting at 1 for Jan
#  @param <day:int>  Day of the month
#  @param <hour:int> Hour 0-23
#  @param <min:int>  Minutes 0-59
#  @param <sec:int>  Seconnds 0-59
#  @return Returns a big number representing the number of seconds since Jan 1, 1970
##
function calendar_to_bn_epoch(year, mon, day, hour, min, sec)
{
   local_var epoch_bn;

   #Make it bulletproof
   if(isnull(year) || typeof(year) != 'int' || year < 0) year = 0;
   if(isnull(mon) || typeof(mon) != 'int' || mon <= 0) mon = 1;
   if(isnull(day) || typeof(day) != 'int' || day <= 0) day= 1;
   if(isnull(hour) || typeof(hour) != 'int' || hour < 0) hour= 0;
   if(isnull(min) || typeof(min) != 'int' || min < 0) min= 0;
   if(isnull(sec) || typeof(sec) != 'int' || sec < 0) sec= 0;

   #Normalize the inputs - this allows date/time differences to be calculated
   if(sec >= 60)
   {
     min += sec / 60;
     sec = sec % 60;
   }

   if(min >= 60)
   {
     hour += min / 60;
     min = min % 60;
   }

   if(hour >= 24)
   {
     day += hour / 24;
     hour = hour % 24;
   }

   if(mon >= 12)
   {
     year += mon / 12;
     mon = mon % 12;
   }

   var days = 0;
   if(mon <= 2)
     year--;
   if(year < 0)
     year = year - 399;

   var era = year/400;
   var yoe = year - era * 400;

   var m = 9;
   if(mon > 2)
     m = -3;
   var doy = (153*(mon + m) + 2)/5 + day - 1;

   var doe = yoe * 365 + yoe/4 - yoe/100 + doy;
   doe = era * 146097 + int(doe) - 719468;

   # Days
   epoch_bn = bn_dec2raw(doe);

   # To hours
   epoch_bn = bn_mul(epoch_bn, bn_dec2raw(24));
   epoch_bn = bn_add(epoch_bn, bn_dec2raw(hour));

   # To minutes
   epoch_bn = bn_mul(epoch_bn, bn_dec2raw(60));
   epoch_bn = bn_add(epoch_bn, bn_dec2raw(min));

   # To seconds
   epoch_bn = bn_mul(epoch_bn, bn_dec2raw(60));
   epoch_bn = bn_add(epoch_bn, bn_dec2raw(sec));

   return epoch_bn;
}


##
# Converts an ASN1 UTCTIME value into Unix Epoch time.
#
# @param  string UTCTIME in UTCTIME representation
#
# @return int unixtime as integer
##
function utctime_to_unixtime(utctime)
{
  local_var output, year, month, day, hour, minute, second;

  if (isnull(utctime)) utctime = _FCT_ANON_ARGS[0];
  if (isnull(utctime))
  {
    err_print("utctime_to_unixtime(): missing required arg 'utctime'");
    return -1;
  }

  # YYMMDDhhmm[ss]Z
  # 150928230106Z

  year = int(substr(utctime, 0, 1));
  if (year > 50)
    year += 1900;
  else
    year += 2000;

  month = int(substr(utctime, 2, 3));
  day = int(substr(utctime, 4, 5));
  hour = int(substr(utctime, 6, 7));
  minute = int(substr(utctime, 8, 9));
  second = int(substr(utctime, 10, 11));

  output = mktime(
    year:year,
    mon:month,
    mday:day,
    hour:hour,
    min:minute,
    sec:second
  );

  return output;
}

namespace datetime
{
  ##
  # Return difference of two times from gettimeofday()
  #
  # @param [begin:string] begin time returned from gettimeofday()
  # @param [end:string] end time returned from gettimeofday()
  #
  # @remark gettimeofday() example: 1543599842.084270
  #
  # @return [string] time difference in the format seconds.microseconds
  ##
  function timeofday_diff(begin, end)
  {
    var integer_digits, fractional_digits;

    if (isnull(begin) || isnull(end))
    {
      err_print(FUNCTION_NAME + "(): missing argument 'begin' or 'end'");
      return -1;
    }

    begin = split(begin, sep:'.', keep:FALSE);
    end   = split(end, sep:'.', keep:FALSE);

    integer_digits    = int(end[0]) - int(begin[0]);
    fractional_digits = int(end[1]) - int(begin[1]);

    # Convert negative to positive
    if (fractional_digits < 0)
    {
      fractional_digits += 1000000;
      integer_digits--;
    }

    # Prefix fractional digits with zeroes (e.g. 084270, 000372)
    fractional_digits = crap(data:'0', length:6 - strlen(string(fractional_digits))) + fractional_digits;

    return integer_digits + "." + fractional_digits;
  }
}
