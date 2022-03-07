#TRUSTED 6354326d21623b10550e3d2ede10ba3dfc2d853a82de24cfc011063cac73ccf9c5f3d2e16efa7ecce808059778e7bf0a2f68ed2f5ecbf5f85618b748e1dc1532b577ae6938bff2d5bfc4bb5d5716369a87e595a941948c85f5e93a5162686a325a967764019bddbf2823b9676f9fbdc7bb6e2f2686b4ab8ae28c14eea2f88b56ecd05c11f39d8018ef8cbe24b992116c1b4d1e4d7303952136690469d3d907b5db5a47033a257fb4a86d7b8b88c34312c6d72533d7c735ce2a44dc3cd7f9fef44f44b1fcccb8b4dccbc3968bb5c570ada3139152ab262eb340eefef7f1a2fc35cb2409fb29716f474fcfbb7f840693aaa83fbee7267437bbebb54604928c350aecece093a1fcb1c48205fceb07fe94cd55700a3e3170258f77f1df5f2a0e7e3f773b27742b91da2ff358b45d029862b4c781cd9baf270de5f4cb3e08948c65df7f2a0df2899fb86a0a146b825add6ecb33afc18e600d9196da2bcf5c809d0396fbe2ebc17f9911bba0758563f9f72433bade4f8d3803eb71a89b89804b5983f353fa4f847814589e489d6d8a677654771490fee6f64a5695b49ea274f00f558655af17499ac86645955f5b0991e9f6509085e601ce5f809a28c141c6fd846236a47b2a60cf73bd04ff99b1eb386917888d2ef1111774137625fd9e2506e437d0d8a03b93c8e3a7f29e59d9eadb41c7ef2ff57183c9d1e50d53f3f60905f7a681
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security, Inc.
#
# @NOGPL@
#
# string_printf.inc
#
# Revision: 1.3
#

include("obj_nlib.inc");
include("path.inc");

global_var
  _FORMAT_STATE_NEW,
  _FORMAT_STATE_PERCENT,
  _FORMAT_STATE_KEYWORD,
  _FORMAT_STATE_FLAGS,
  _FORMAT_STATE_WIDTH,
  _FORMAT_STATE_PRECISION,
  _FORMAT_STATE_TYPE,
  _FORMAT_STATE_READY,
  _FORMAT_STATE_DONE;

_FORMAT_STATE_NEW       = 0;
_FORMAT_STATE_PERCENT   = 1;
_FORMAT_STATE_KEYWORD   = 2;
_FORMAT_STATE_FLAGS     = 3;
_FORMAT_STATE_WIDTH     = 4;
_FORMAT_STATE_PRECISION = 5;
_FORMAT_STATE_TYPE      = 6;
_FORMAT_STATE_READY     = 7;
_FORMAT_STATE_DONE      = 8;

##
# Internal function for the printf suite of functions. Handles
# choosing the source of data for the current format specifier.
#
# @param args  The array of arguments passed to sprintf.
# @param state The current state table.
#
# @return The data to be used.
##
function _get_printf_arg(args, state)
{
  local_var arg;

  if (max_index(state["keywords"]) > 1)
    arg = path_get(args:state["keywords"]);
  else
    arg = args[state["args_pos"]];

  return arg;
}

##
# Internal state-machine function for the printf suite of functions. Handles
# the state where the string is being read, as normal.
#
# If the string ends, move to the DONE state.
#
# If the string contains a '%' (a format indicator), go to the PERCENT state.
#
# Everything else, just add to the string.
#
# @param state The current state table.
# @param c     The current character.
#
# @return The new state table.
##
function _handle_format_state_new(c, state)
{
  if (isnull(c))
  {
    state["state"] = _FORMAT_STATE_DONE;
  }
  else if (c == "%")
  {
    state["state"] = _FORMAT_STATE_PERCENT;
    state["format_pos"]++;
  }
  else
  {
    state["result"] += c;
    state["format_pos"]++;
  }

  return state;
}

##
# Internal state-machine function for the printf suite of functions. Handles
# the state where a percent sign has just been read and we're processing the
# next character. This state is only necessary because of the potential '%%'
# construct (which adds a single percent sign to the string).
#
# If the string ends, add the '%' to the string and move to the DONE state.
#
# If the next character is a '%', add a single '%' to the string and return to
# the NEW state.
#
# If the next character is a '(', go to the KEYWORD state.
#
# If the next character is a letter, go to the TYPE state.
#
# If the next character is a number, go to the WIDTH state.
#
# Everything else, go to FLAGS.
#
# @param state The current state table.
# @param c     The current character.
#
# @return The new state table.
##
function _handle_format_state_percent(c, state)
{
  if (isnull(c))
  {
    state["result"] += "%";
    state["state"] = _FORMAT_STATE_DONE;
  }
  else if (c == "(")
  {
    if (isnull(state["kw"]))
      exit(1, "vsprintf used a keyword lookup when no keywords were provided.");

    # Start a new keyword.
    state["keywords"][max_index(state["keywords"])] = "";

    state["format_pos"]++;
    state["state"] = _FORMAT_STATE_KEYWORD;
  }
  else if (c == "%")
  {
    state["result"] += "%";
    state["format_pos"]++;
    state = _printf_reset_state(state:state);
  }
  else if (c =~ "^[a-zA-Z]$")
  {
    state["state"] = _FORMAT_STATE_TYPE;
  }
  else if (c =~ "^[0-9]$")
  {
    state["state"] = _FORMAT_STATE_WIDTH;
  }
  else
  {
    state["state"] = _FORMAT_STATE_FLAGS;
  }

  return state;
}

##
# Internal state-machine function for the printf suite of functions. Handles
# the state where a '%(' has just been read and we're processing a keyword.
#
# If the string ends, go to the DONE state (technically invalid).
#
# If the character is a ')', go to PERCENT.
#
# Everything else, stay in this state.
#
# @param state The current state table.
# @param c     The current character.
#
# @return The new state table.
##
function _handle_format_state_keyword(c, state)
{
  if (isnull(c))
  {
    state["state"] = _FORMAT_STATE_DONE;
  }
  else if (c == ")")
  {
    state["state"] = _FORMAT_STATE_PERCENT;
    state["format_pos"]++;
  }
  else
  {
    # Append character to the last keyword.
    state["keywords"][max_index(state["keywords"]) - 1] += c;
    state["format_pos"]++;
  }

  return state;
}

##
# Internal state-machine function for the printf suite of functions. Handles
# the state where a percent sign has just been read and we're processing non-
# alphanumeric data (ie, flags).
#
# If the string ends, go to the DONE state (technically invalid).
#
# If the character is a digit, go to WIDTH.
#
# If the character is a period, go to PRECISION.
#
# If the character is a valid flag, set the appropriate value and continue
# reading flags.
#
# Everything else, go to TYPE.
#
# @param state The current state table.
# @param c     The current character.
#
# @return The new state table.
##
function _handle_format_state_flags(c, state)
{
  if (isnull(c))
  {
    state["state"] = _FORMAT_STATE_DONE;
  }
  else if (c == "+")
  {
    state["leading_plus"] = TRUE;
    state["format_pos"]++;
  }
  else if (c == " ")
  {
    state["leading_space"] = TRUE;
    state["format_pos"]++;
  }
  else if (c == "#")
  {
    state["alternate_form"] = TRUE;
    state["format_pos"]++;
  }
  else if (c == "-")
  {
    state["left_justify"] = TRUE;
    state["format_pos"]++;
  }
  else if (c == ".")
  {
    state["state"] = _FORMAT_STATE_PRECISION;
    state["format_pos"]++;
  }
  else if (c =~ "^[0-9]$")
  {
    state["state"] = _FORMAT_STATE_WIDTH;
  }
  else
  {
    state["state"] = _FORMAT_STATE_TYPE;
  }

  return state;
}

##
# Internal state-machine function for the printf suite of functions. Handles
# the state where we're reading the numerical field-width value.
#
# If the string ends, go to the DONE state (technically invalid).
#
# If the character is a digit, continue reading the WIDTH.
#
# If the character is a period, go to PRECISION.
#
# Everything else, go to TYPE.
#
# @param state The current state table.
# @param c     The current character.
#
# @return The new state table.
##
function _handle_format_state_width(c, state)
{
  if (isnull(c))
  {
    state["state"] = _FORMAT_STATE_DONE;
  }
  else if (c =~ "^[0-9]$")
  {
    # Handle format specifiers that start with 0
    if (state["width"] == 0 && c == "0")
      state["state"] = _FORMAT_STATE_PRECISION;
    else
      state["width"] = (state["width"] * 10) + int(c);
    state["format_pos"]++;
  }
  else if (c == ".")
  {
    state["state"] = _FORMAT_STATE_PRECISION;
    state["format_pos"]++;
  }
  else
  {
    state["state"] = _FORMAT_STATE_TYPE;
  }

  return state;
}

##
# Internal state-machine function for the printf suite of functions. Handles
# the state where we're reading the numerical precision value (comes after a
# period or zero, tells it how many zeroes or appropriately signed bytes to
# to add to the front of the format string).
#
# If the string ends, go to the DONE state (technically invalid).
#
# If the character is a digit, continue reading the PRECISION.
#
# Everything else, go to TYPE.
#
# @param state The current state table.
# @param c     The current character.
#
# @return The new state table.
##
function _handle_format_state_precision(c, state)
{
  if (isnull(c))
  {
    state["state"] = _FORMAT_STATE_DONE;
  }
  else if (c =~ "^[0-9]$")
  {
    state["precision"] = (state["precision"] * 10) + int(c);
    state["format_pos"]++;
  }
  else
  {
    state["state"] = _FORMAT_STATE_TYPE;
  }

  return state;
}

##
# Internal state-machine function for the printf suite of functions. Handles
# the state where we're reading the one-character type.
#
# If the string ends, go to the DONE state (technically invalid).
#
# Anything else, read as a type and move to the READY state.
#
# @param state The current state table.
# @param c     The current character.
#
# @return The new state table.
##
function _handle_format_state_type(c, state)
{
  if (isnull(c))
  {
    state["state"] = _FORMAT_STATE_DONE;
  }
  else
  {
    state["type"] = c;
    state["state"] = _FORMAT_STATE_READY;
    state["format_pos"]++;
  }

  return state;
}

##
# Format a %b or %B string - binary.
#
# Returns the base-2 (binary) string formatted as specified by the various
# format specifiers.
#
# @param state The current format string state.
# @param args  The array of arguments passed to sprintf.
#
# @return The formatted string.
##
function _format_b(args, state)
{
  local_var current_arg, value, prepend;

  current_arg = _get_printf_arg(state:state, args:args);

  # If we're using the alternate form, prepend 0b to the string
  prepend = "";
  if (state["alternate_form"])
    prepend = "0b";

  value = ltostr(current_arg,
    base            : 2,
    twos_complement : !state["leading_plus"],
    width           : state["width"],
    precision       : state["precision"],
    leading_plus    : state["leading_plus"],
    leading_space   : state["leading_space"],
    left_justify    : state["left_justify"],
    prepend         : prepend
  );

  # If %B was given as the type, uppercase the string
  if (state["type"] == "B")
    value = toupper(value);

  return value;
}

##
# Format a %o string - octal.
#
# Returns the base-8 (octal) string formatted as specified by the various
# format specifiers.
#
# @param state The current format string state.
# @param args  The array of arguments passed to sprintf.
#
# @return The formatted string.
##
function _format_o(args, state)
{
  local_var current_arg, value, prepend;

  current_arg = _get_printf_arg(state:state, args:args);

  # If the alternate form is requested, prepend a '0' to the string
  prepend = "";
  if (state["alternate_form"])
    prepend = "0";

  value = ltostr(current_arg,
    base            : 8,
    twos_complement : !state["leading_plus"],
    width           : state["width"],
    precision       : state["precision"],
    leading_plus    : state["leading_plus"],
    leading_space   : state["leading_space"],
    left_justify    : state["left_justify"],
    prepend         : prepend
  );

  return value;
}

##
# Format a %d string - decimal. Also handles %i and %u, which are the same.
#
# Returns the base-10 (decimal) string formatted as specified by the various
# format specifiers.
#
# @param state The current format string state.
# @param args  The array of arguments passed to sprintf.
#
# @return The formatted string.
##
function _format_d(args, state)
{
  local_var precision;

  precision = state["precision"];

  return ltostr(_get_printf_arg(state:state, args:args),
    base          : 10,
    width         : state["width"],
    precision     : precision,
    leading_plus  : state["leading_plus"],
    leading_space : state["leading_space"],
    left_justify  : state["left_justify"]
  );
}

##
# Format a %x string - hex.
#
# Returns the base-16 (hex) string formatted as specified by the various
# format specifiers.
#
# @param state The current format string state.
# @param args  The array of arguments passed to sprintf.
#
# @return The formatted string.
##
function _format_x(args, state)
{
  local_var current_arg, precision, value, prepend;

  current_arg = _get_printf_arg(state:state, args:args);
  precision   = state["precision"];
  prepend     = "";
  if (state["alternate_form"])
    prepend = "0x";

  value = ltostr(current_arg,
    base            : 16,
    twos_complement : !state["leading_plus"],
    width           : state["width"],
    precision       : precision,
    leading_plus    : state["leading_plus"],
    leading_space   : state["leading_space"],
    left_justify    : state["left_justify"],
    prepend         : prepend
  );

  if (state["type"] == "X")
    value = toupper(value);

  return value;
}

##
# Format a %s string.
#
# Returns the string formatted as specified by the various format specifiers.
#
# @param state The current format string state.
# @param args  The array of arguments passed to sprintf.
#
# @return The formatted string.
##
function _format_s(args, state)
{
  local_var current_arg, value;

  current_arg = _get_printf_arg(state:state, args:args);

  value = string(current_arg);

  if (state["precision"])
    value = left(value, state["precision"]);
  if (state["left_justify"]) value = rpad(value, state["width"], char:" ");
  else value = lpad(value, state["width"], char:" ");

  return value;
}

##
# Format a %c character.
#
# Returns the integer converted into a character.
#
# @param state The current format string state.
# @param args  The array of arguments passed to sprintf.
#
# @return The formatted string.
##
function _format_c(args, state)
{
  local_var current_arg, value;

  current_arg = _get_printf_arg(state:state, args:args);

  value = raw_string(current_arg);
  if (state["left_justify"]) value = rpad(value, state["width"], char:" ");
  else value = lpad(value, state["width"], char:" ");

  return value;
}

##
# Format a %p character.
#
# Returns the object formatted as code.
#
# @param state The current format string state.
# @param args  The array of arguments passed to sprintf.
#
# @return The formatted string.
##
function _format_p(args, state)
{
  return obj_rep(_get_printf_arg(state:state, args:args));
}

##
# Format a %t character.
#
# Returns the list formatted as a table.
#
# @param state The current format string state.
# @param args  The array of arguments passed to sprintf.
#
# @return The formatted string.
##
function _format_t(args, state)
{
  local_var current_arg, i, len, max, num, value;

  current_arg = _get_printf_arg(state:state, args:args);

  # Find the longest of the names.
  max = 0;
  num = max_index(current_arg);
  for (i = 0; i + 1 < num; i += 2)
  {
    len = strlen(current_arg[i]);
    if (len > max)
      max = len;
  }

  # Format each name/value pair in a table.
  value = "";
  for (i = 0; i + 1 < num; i += 2)
  {
    value +=
      crap(data:" ", length:state["width"]) +
      rpad(current_arg[i], max, char:" ") +
      " : " +
      current_arg[i + 1] +
      '\n';
  }

  return value;
}

##
# Internal state-machine function for the printf suite of functions. Handles
# the state where we're finished reading the specifier, and all that's left is
# to build the string.
#
# This always returns to the READY state.
#
# @param state The current state table.
# @param c     The current character.
# @param args  The arguments array the user passed.
#
# @return The new state table.
##
function _handle_format_state_ready(args, c, state)
{
  if (tolower(state["type"]) == "b")
    state["result"] += _format_b(state:state, args:args);
  else if (state["type"] == "c")
    state["result"] += _format_c(state:state, args:args);
  else if (state["type"] =~ "[diu]")
    state["result"] += _format_d(state:state, args:args);
  else if (state["type"] == "o")
    state["result"] += _format_o(state:state, args:args);
  else if (tolower(state["type"]) == "p")
    state["result"] += _format_p(state:state, args:args);
  else if (state["type"] == "s")
    state["result"] += _format_s(state:state, args:args);
  else if (tolower(state["type"]) == "t")
    state["result"] += _format_t(state:state, args:args);
  else if (tolower(state["type"]) == "x")
    state["result"] += _format_x(state:state, args:args);
  else
    return NULL;

  # Consume an argument if a keyword was not used.
  if (max_index(state["keywords"]) <= 1)
    state["args_pos"]++;

  state = _printf_reset_state(state:state);

  return state;
}

##
# Internal state-machine function that resets the state to the default.
# Note that this doesn't reset every veriable, some state is maintained.
#
# @param state The current state.
#
# @return The state with the variables reset.
##
function _printf_reset_state(state)
{
  state["state"]          = _FORMAT_STATE_NEW;
  state["precision"]      = 0;
  state["width"]          = 0;
  state["pad_with_zero"]  = FALSE;
  state["leading_plus"]   = FALSE;
  state["leading_space"]  = FALSE;
  state["alternate_form"] = FALSE;
  state["left_justify"]   = FALSE;

  # Note that a path object is similar to a list, so we need to treat
  # it as such when adding it to another list.
  state["keywords"]       = make_list();
  state["keywords"][0]    = state["kw"];

  return state;
}

##
# Convert the args into a string, based on the format string.
#
# This conforms, for the most part, to ruby's Kernel.sprintf()
# function (with a few rare edgecases handled differently). The
# following is the format:
#
#   %[(keyword)...][flags][width][<.>precision][type]
#
# Note that Python's %(keyword) format is also supported, so you can
# have re-usable named arguments as well.
#
# The following flags are supported:
#
#   <space>  : Put a space at the start of all non-negative numbers.
#   #        : Use the alternate form. eg: %x becomes 0x<number>.
#   +        : Add a leading plus to non-negative numbers.
#   -        : Left-justify the result.
#   0 (zero) : Pad with zeroes, not spaces.
#
# The following flags are *NOT* supported:
#
#   <digit>$ : Use an absolute argument number.
#   *        : Use the next argument as the field width.
#
# The width represents the minimum amount of space the field can take
# up. If the string is shorter than the width, it's padded with spaces
# (unless a flag indicates otherwise) up to the proper size.
#
# The precision is the number of zeroes (or sign bytes in the case of
# twos' complement values) to pad the value with. In the case of
# string, this will truncate strings that are too short.
#
# And finally, the following types are supported:
#
#   %b and %B : Base 2 (binary)
#   %o        : Base 8 (octal)
#   %d        : Base 10 (decimal)
#   %i        : Same as %d
#   %u        : Same as %d
#   %x and %X : Base 16 (hex)
#   %s        : String
#   %c        : Character
#   %p        : Object representation via obj_rep()
#   %t        : Table-formatted list for reports
#
# The following types are *not* supported:
#
#   %e, %E, %f, %F, %g, %G, %a, %a : Floating point
#
# And finally:
#
#   %% : A double percent becomes a single percent
#
# @param format The format string.
# @param args   The list of arguments.
# @param kw     The list of keyword arguments.
#
# @return A string representing the format string with the args inserted.
##
function vsprintf(args, format, kw)
{
  local_var state, c, i;

  # Create the initial state.
  state = make_array();
  state["format_pos"] = 0;
  state["args_pos"] = 0;

  # Store the keywords using the path library, to guard against making
  # repeated copies of data in the event of a large data structure
  # being passed in.
  if (!isnull(kw))
    state["kw"] = path_store(kw);

  # Reset the state to where no format is in progress.
  state = _printf_reset_state(state:state);

  # If there was no format passed in, and args is not empty, assume
  # that the first element of args is the format. If there's no first
  # element, error out.
  if (isnull(format))
  {
    if (max_index(args) == 0)
      exit(1, "vsprintf was not implicitly nor explicitly given a format.");

    format = args[0];
    state["args_pos"] = 1;
  }

  while (state["state"] != _FORMAT_STATE_DONE)
  {
    c = NULL;
    if (state["format_pos"] < strlen(format))
      c = format[state["format_pos"]];

    if (state["state"] == _FORMAT_STATE_NEW)
      state = _handle_format_state_new(state:state, c:c);
    else if (state["state"] == _FORMAT_STATE_PERCENT)
      state = _handle_format_state_percent(state:state, c:c);
    else if (state["state"] == _FORMAT_STATE_KEYWORD)
      state = _handle_format_state_keyword(state:state, c:c);
    else if (state["state"] == _FORMAT_STATE_FLAGS)
      state = _handle_format_state_flags(state:state, c:c);
    else if (state["state"] == _FORMAT_STATE_WIDTH)
      state = _handle_format_state_width(state:state, c:c);
    else if (state["state"] == _FORMAT_STATE_PRECISION)
      state = _handle_format_state_precision(state:state, c:c);
    else if (state["state"] == _FORMAT_STATE_TYPE)
      state = _handle_format_state_type(state:state, c:c);
    else if (state["state"] == _FORMAT_STATE_READY)
      state = _handle_format_state_ready(state:state, c:c, args:args);
    else
      exit(1, "vsprintf ended up in an invalid state: " + state["state"] + ".");
  }

  # Free the keywords stored in the path library.
  if (!isnull(kw))
    path_free(state["kw"]);

  return state["result"];
}

##
# @see vsprintf(). This is the same thing, except the arguments are anonymous.
##
function sprintf(format, kw)
{
  return vsprintf(format:format, args:_FCT_ANON_ARGS, kw:kw);
}

##
# @see vsprintf(). This is the same thing, except it displays the result to the screen.
##
function vprintf(args, format, kw)
{
  display(vsprintf(format:format, args:args, kw:kw));
}

##
# @see vsprintf(). This is the same thing, except the arguments are anonymous
#      and the result is printed to the screen.
##
function printf(kw)
{
  vprintf(args:_FCT_ANON_ARGS, kw:kw);
}
