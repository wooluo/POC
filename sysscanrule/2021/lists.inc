#TRUSTED a06f1fb04ff97bce044381933536b4fafd27140c54cfe03013317071d6200152c8066e1dbed2f80d2c28462a11674d2ffe6848b6f56f60b6416e5ac19cc29c3834378f00b6ad23f4436c1900eec9572d97b4595ed69e8bea6a1a3d7cfe43eff729f6dd3a5575511dc91bda5ee36a9bd334ebd195b74f970c3faade166076537a9cdf94120914a56e1db2a2ed279279c7a04e07b0826c67daf7b334ebc8603932c9f84bfadefc6b6ca9a6f1324d41c01794aa2c518d1af66b4dac1554f8332c45336705094951c399553e557fb77521f9af185a5ab3ab20620c07ff9c052f0e84fee5670c94126397c659711f3f47cbfdddaba663a20610ad57d6eb710b82a497894e885d1cab485931bf72c51e9e182f3508e6c7d0ff7f448cdfcebe4da9367ea2d01a86e1d3668c58a263e575c1c12e10f81299b3fc114e931f363049fb35fc8408c1fde295856ab94182e146315ba77b61b851123ddf52c54e8931aa5ecb7e345e2a9582804c2a2b8b5b5502b0df9b7b20dffa0ff56ba630f2d633165c84eb6fc91187f05200a59f6bcb00e0be0dca59aa13fb08f14f8d0fb63a678bf69ca7fa9542dc4daabbabe16ec54ef64d10241bf5044157dc742402897f4ca41f16b3bc88b2a39cc032892b25db4e1ede73f63030a7525d3ef5613d87245491bd6f0f3c2e3ca05496a1c6a86e3cf0306242c45b9a2f6c9f562bb648bbeceeea238ada
###
# 
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# A suite of tools to better allow for a functional style of programming in NASL,
# together with functions for creating and manipulating lists and sets.
#
# Revision: 1.2
###

include("compat_shared.inc");

namespace collib {

global_var _DEBUG_ = 0;

function dbgprint () { if (_DEBUG_) display(_FCT_ANON_ARGS[0]+'\n'); }

# First, we'll need to functionalize a few basic operators, since NASL
# doesn't have lambda expressions.

##
# @anonparam 1st the value to be returned
# @return 1st
# @remark id() is just the identity function, which we need in order
# to write certain higher-order functions in the simplest and clearest
# fashion.
##
function id()  { return _FCT_ANON_ARGS[0]; }

##
# @anonparam 1st any type that can be compared via '>'
# @anonparam 2nd any type comparable with 1st, via '>'
# @return boolean
# @remark gt() is a functional expression of the greater-than operator.
##
function gt()  { return _FCT_ANON_ARGS[0] > _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st any type that can be compared via '>='
# @anonparam 2nd any type comparable with 1st, via '>='
# @return boolean
# @remark ge() is a functional expression of the '>=' operator.
##
function ge()  { return _FCT_ANON_ARGS[0] >= _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st any type that can be compared via '<'
# @anonparam 2nd any type comparable with 1st, via '<'
# @return boolean
# @remark lt() is a functional expression of the lesser-than operator.
##
function lt()  { return _FCT_ANON_ARGS[0] < _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st any type that can be compared via '<='
# @anonparam 2nd any type comparable with 1st, via '<='
# @return boolean
# @remark lt() is a functional expression of the '<=' operator.
##
function le()  { return _FCT_ANON_ARGS[0] <= _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st any type that can be compared via '=='
# @anonparam 2nd any type comparable with 1st, via '=='
# @return boolean
# @remark eq() is a functional expression of the equality operator.
##
function eq()  { return _FCT_ANON_ARGS[0] == _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st boolean
# @anonparam 2nd boolean
# @return boolean TRUE if 1st or 2nd are TRUE, FALSE otherwise.
# @remark functional expression of the or (||) operator.
##
function or()  { return _FCT_ANON_ARGS[0] || _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st boolean
# @anonparam 2nd boolean
# @return boolean TRUE if 1st and 2nd are TRUE, FALSE otherwise.
# @remark functional expression of the and (&&) operator.
##
function and() { return _FCT_ANON_ARGS[0] && _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st integer
# @anonparam 2nd integer
# @return integer the sum of 1st and 2nd
# @remark functional expression of the '+' operator.
##
function plus() { return _FCT_ANON_ARGS[0] + _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st integer
# @anonparam 2nd integer
# @return integer the difference of 1st and 2nd
# @remark functional expression of the '-' operator.
##
function minus() { return _FCT_ANON_ARGS[0] - _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st integer
# @anonparam 2nd integer
# @return integer the product of 1st and 2nd
# @remark functional expression of the '*' operator.
##
function times() { return _FCT_ANON_ARGS[0] * _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st the list of items to search the 1st list for
# @anonparam 2nd the list to search in
# @return boolean TRUE if all the items supplied are in the list,
# and FALSE otherwise.
# @remark See if all items in 'items' are in 'list'.
##
function is_sublist()
{
  var list = _FCT_ANON_ARGS[1];
  var items = _FCT_ANON_ARGS[0];

  var item;
  var length = max_index(items);
  var i;
  for (i = 0; i < length; i++)
  {
    item = items[i];
    if (!contains(list, item))
    {
      return FALSE;
    }
  }
  return TRUE;
}

##
# @anonparam 1st the list to search in
# @anonparam 2nd the list of items to search the 1st list for
# @return boolean TRUE if all the items supplied are in the list,
# and FALSE otherwise.
# @remark See if all items in 'items' are in 'list'.
##
function is_superlist()
{
  var list = _FCT_ANON_ARGS[0];
  var items = _FCT_ANON_ARGS[1];

  var item;
  var i, length;
  length = max_index(list);
  for (i = 0; i < length; i++)
  {
    item = list[i];
    if (!contains(list, item))
    {
      return FALSE;
    }
  }
  return TRUE;
}


##
# @param compare function pointer, an optional comparator function to use instead
# of '=='
# @param args list of arguments to pass to f along with its arguments from
# the list being searched. The order in which the variables are passed is
# as follows: f(item, i, args[0], args[1], ..., args[n]) for each i in list.
# @anonparam 1st the list to be searched
# @anonparam 2nd the item to search for
# @return boolean, TRUE if the item (2nd) is contained in 1st, FALSE otherwise
##
function contains(compare, args, list, item)
{
  var ap_args, x;
  if (isnull(list)) list = _FCT_ANON_ARGS[0];
  if (isnull(item)) item = _FCT_ANON_ARGS[1];
  if (isnull(args)) args = [];

  var i, length;
  length = max_index(list);
  for (i = 0; i < length; i++)
  {
    x = list[i];
    if (isnull(compare) && typeof(x) == typeof(item) &&
        equals(x,item))
    {
      return TRUE;
    }
    ap_args = make_list2(item, x);
    var arg;
    var arg_idx, num_args;
    num_args = max_index(args);
    for (arg_idx = 0; arg_idx < num_args; arg_idx ++)
    {
      arg = args[arg_idx];
      push(arg, ap_args);
    }
    if (!isnull(compare) && apply(f:compare, args:ap_args))
    {
      return TRUE;
    }
  }
  return FALSE;
}

##
# @anonparam 1st the list to be searched
# @anonparam 2nd the item to search for
# @return the index value of 1st found item in list, -1 if the item is not found
##
function getIndex(list, item)
{
  if (isnull(list)) list = _FCT_ANON_ARGS[0];
  if (isnull(item)) item = _FCT_ANON_ARGS[1];
  var length = max_index(list);
  for (var i = 0; i < length; i++)
  {
    if (equals(list[i], item))
      return i;
  }
  return -1;
}

##
# @anonparam 1st list
# @anonparam 2nd list
# @return a list containing only those elements belonging to both
# 1st and 2nd.
# @remark This function performs the set-theoretic intersection operation,
# and returns the result. It can be applied only to lists.
##
function intersection(f)
{
  var listA, listB;
  listA = _FCT_ANON_ARGS[0];
  listB = _FCT_ANON_ARGS[1];
  var intersection_list = make_list();
  var item;
  var i, length = max_index(listA);
  for (i = 0; i < length; i++)
  {
    item = listA[i];
    if (contains(listB, item))
    {
      push(item, intersection_list);
    }
  }
  return intersection_list;
}

##
# @anonparam 1st list
# @anonparam 2nd list
# @return a list containing only those elements belonging to both
# 1st and 2nd.
# @remark This function performs the set-theoretic union operation,
# and returns the result. It can be applied only to lists.
##
function union()
{
  var listA, listB;
  listA = _FCT_ANON_ARGS[0];
  listB = _FCT_ANON_ARGS[1];
  return make_list(listA, listB);
}

##
# @anonparam 1st list
# @anonparam 2nd list
# @param f a function pointer to a comparator to use in place of '==' when
# assessing membership in 2nd parameter, when 2nd parameter is a list
# @return a list containing only those elements belonging to 1st
# but not to 2nd.
# @remark This function performs the set-theoretic union operation,
# and returns the result. It can be applied only to lists.
##
function subtract()
{
  var listA, listB;
  listA = _FCT_ANON_ARGS[0];
  listB = _FCT_ANON_ARGS[1];

  var diff = make_list();
  var item;
  # safe from recursive foreach -- fresh pointer
  foreach item (listA)
  {
    if (!contains(listB, item))
    {
      push(item, diff);
    }
  }
  return diff;
}

##
# @anonparam 1st list
# @anonparam 2nd list
# @return list containing only those elements that do not
# belong to the intersection of 1st and 2nd.
##
function difference ()
{
  return make_list(subtract(_FCT_ANON_ARGS[0], _FCT_ANON_ARGS[1]),
                   subtract(_FCT_ANON_ARGS[1], _FCT_ANON_ARGS[0]));
}

##
# @anonparam list
# @return a list of unique elements contained in the list, with
# repetitions removed.
# @remark This function runs in O(n^2) time. If the list
# is known to contain only hashable types, then it's better
# to remove duplicates like so:
#     s = new('set',list);
#     new_list = s.to_list();
##
function remove_duplicates()
{
  var item, new_list = [];
  var list = _FCT_ANON_ARGS[0];
  foreach (item in list)
    if (!contains(new_list, item))
      push(item, new_list);
  return new_list;
}


##
# @param f a function pointer
# @anonparam list of arguments for f
# @return the result of calling f with the arguments supplied in list
# @remark Usage: apply(f:func, [1, 2, 3]); is the same as func(1, 2, 3)
# currently only set up to work for functions with 8 or fewer arguments,
##
function apply(f, args)
{
  if (isnull(args)) args = _FCT_ANON_ARGS[0];
  var num_args = max_index(args);

  if (num_args == 0) return f();
  else if (num_args == 1) return f(args[0]);
  else if (num_args == 2) return f(args[0], args[1]);
  else if (num_args == 3) return f(args[0], args[1], args[2]);
  else if (num_args == 4) return f(args[0], args[1], args[2], args[3]);
  else if (num_args == 5) return f(args[0], args[1], args[2], args[3], args[4]);
  else if (num_args == 6) return f(args[0], args[1], args[2], args[3], args[4], args[5]);
  else if (num_args == 7) return f(args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
  else if (num_args == 8) return f(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
  else exit(1, "apply() is not yet implemented for "+max_index(args)+" arguments.");
}


# The next two functions (range and enumerate) are so we can get rid of for(i=0;i<length(bla);i++) completely

##
# @anonparam integer lower bound, inclusive
# @anonparam integer upper bound, exclusive
# @return list of integers from lower bound to upper bound
# @remark Usage: foreach (number in range(0, 5))  # number takes on the values 0, 1, 2, 3, 4
##
function range()
{
  var start = _FCT_ANON_ARGS[0];
  var end = _FCT_ANON_ARGS[1];
  if (isnull(end))
  {
    end = start;
    start = 0;
  }
  var result = make_list();
  var i;
  for (i=start; i<end; i++)
  {
    push(i, result);
  }
  return result;
}

##
# @anonparam list of elements of type T
# @return list of arrays, of the form {'index': integer, 'val': T}
# @remark
# Usage:
# for (book in enumerate(books))
# {
#   display(book.index + ': ' + book.val);
# }
##
function enumerate()
{
  var list = _FCT_ANON_ARGS[0];
  var result = make_list();
  var i;
  for (i=0; i<max_index(list); i++)
  {
    push({'index':i, 'val':list[i]}, result);
  }
  return result;
}


##
# Return a list containing each item in list run through f.
#
# @anonparam The list to run on.
# @param f The function that each item will be run through.
# @param args Optional additional args to be passed to f
# *before* the last argument, taken from the list.
# @return The list [apply(f:\@f, args:args, x) | x in original list]
# @remark
# example: map(f:plus_one, [1,2,3])
#          -> [plus_one(1), plus_one(2), plus_one(3)]
#
# example: map(f:plus, [1,2,3], args:[4]);
#          -> [plus(4,1), plus(4,2), plus(4,3)]
# Note that the arguments are passed in a different order
# here than in the version of apply in the Compliance
# library, functional.inc. This is so as to better
# approximate the implementation of partial application and
# currying, found in most functional languages.
##
function map(f, args)
{
  if (isnull(args))
  {
    args = make_list();
  }
  var item;
  var new_list = make_list();
  var list = _FCT_ANON_ARGS[0];
  # safe from recursive foreach bug -- fresh pointer
  foreach (item in list)
  {
    var ap_args = list_copy(args);
    push(item, ap_args);
    push(apply(f:f, args:ap_args), new_list);
  }
  return new_list;
}

##
# @anonparam list
# @return copy of that list, but not necessarily a copy
# of its elements, which may be aliases
##
function list_copy ()
{
  var item, new_list = [];
  var i, length;
  length = max_index(_FCT_ANON_ARGS[0]);
  for (i = 0; i < length; i++)
  {
    item = _FCT_ANON_ARGS[0][i];
    push(item, new_list);
  }
  return new_list;
}

##
# @anonparam list
# @return recursive copy of a list, including its
# elements, if they're also lists
##
function deep_copy ()
{
  var item, new_list = [];
  var i, length;
  length = max_index(_FCT_ANON_ARGS[0]);
  for (i = 0; i < length; i++)
  {
    item = _FCT_ANON_ARGS[0][i];
    if (typeof_ex(item) == 'list')
      item = deep_copy(item);
    push(item, new_list);
  }
  return new_list;
}


##
# @anonparam The list to run on.
# @param f The function that each item will be checked against.
# @param args Optional additional args to be added to the end of f.
# @return a list containing each item that returns a truthy value when passed through f.
# @remark
# example: filter(f:\@greater_than_3, [1, 2, 3, 4, 5])
#          -> [4, 5]
#
# example: filter(f:\@is_between, [1, 2, 3, 4, 5], args:[3, 5])
#          -> [4]
##
function filter(f, args)
{
  var list = _FCT_ANON_ARGS[0];
  var optional_following_arguments = args;

  if (isnull(optional_following_arguments))
  {
    optional_following_arguments = make_list();
  }

  var item;
  var new_list = make_list();
  var i, length;
  length = max_index(list);
  for (i = 0; i < length; i++)
  {
    item = list[i];
    var ap_args = list_copy(args);
    push(item, ap_args);
    if (apply(f:f, args:ap_args))
      push(item, new_list);
  }
  return new_list;
}


##
# @anonparam The array to run on.
# @param f The function that each item will be checked against.
# @param args Optional additional args to be added to the end of f.
# @return an array containing each key/value pair that returns a truthy value
# when the value is passed through f.
# @remark
# example: filter_array(f:\@greater_than_3, {'a':1, 'b':3, 'c':4})
#          -> {'c':4}
#
# example: filter_array(f:\@is_between, {'a':1, 'b':3, 'c':4, 'd':5}, args:[3, 5])
#          -> {'c':4}
##
function filter_array(f, args)
{
  var array = _FCT_ANON_ARGS[0];
  var optional_following_arguments = args;

  if (isnull(optional_following_arguments))
  {
    optional_following_arguments = make_list();
  }

  var item;
  var new_array = {};
  var key, ar_keys = keys(array);
  var i, length = max_index(ar_keys);
  for (i = 0; i < length; i++)
  {
    key = ar_keys[i];
    item = array[key];
    var ap_args = list_copy(args);
    push(item, ap_args);
    if (apply(f:f, args:ap_args))
      new_array[key] = item;
  }
  return new_array;
}


##
# @anonparam list
# @param f function pointer
# @param args arguments to pass to f along with each element from list
# @return pair p of lists with p[0] being the result of filtering the list
# through f with args, and p[1] being its complement.
# @remark Similar to filter(), except that it returns a pair (list)
# whose first element is a list containing elements of the list for
# which apply(f:f, args:make_list(args,x)) is truthy for x, and whose second
# element contains the remaining elements of the list.
##
function partition(f, args)
{
  var item;
  var list = _FCT_ANON_ARGS[0];

  var results = make_list();
  results[0] = make_list();
  results[1] = make_list();
  var i, length = max_index(list);
  for (i = 0; i < length; i++)
  {
    item = list[i];
    var bin, ap_args = list_copy(args);
    push(item, ap_args);
    if (apply(f:f, args:ap_args))
      bin = 0;
    else
      bin = 1;
    push(item, results[bin]);
  }
  return results;
}

##
# @param accessor, a function pointer to be called on each item
# before sorting. Optional.
# @param comparator, a dyadic boolean-returning function to be
# used instead of '<'. Optional.
# @anonparam list of elements to be sorted
# @return a sorted list of the elements in the list parameter
# @remark
# A mergesort implementation with an optional accessor function.
# The accessor is run on each item before they are sorted.
# comparator is an optional replacement for nasl's builtin '<',
# which is used to sort the values.
##
function merge_sort(accessor, comparator)
{
  var values = _FCT_ANON_ARGS[0];
  if (isnull(accessor)) { accessor = @id; }
  if (isnull(comparator)) { comparator = @lt; }

  if (max_index(values) <= 1)
  {
    return values;
  }

  var partitions = split_in_half(values);

  var left = merge_sort(partitions[0], accessor:accessor, comparator:comparator);
  var right = merge_sort(partitions[1], accessor:accessor, comparator:comparator);

  return merge_sort_merge(left, right, accessor:accessor, comparator:comparator);
}

global_var __vcmp_regex_table__ = NULL; # a hideous hack, but we don't have closures.

###
# Sorts lists of dotted version strings.
# See documentation on ver_compare in misc.func.
#
# @remark For internal use only. Used by version_sort.
# @anonparam First First version to be compared
# @anonparam Second Second version to be compared
#
# @category collib
#
# @return Truthy if the first anonparam has a ver_compare result less than 0
#         Falsy otherwise
##
function _vcmp ()
{
  var v1 = _FCT_ANON_ARGS[0];
  var v2 = _FCT_ANON_ARGS[1];
  return ver_compare(ver:v1, fix:v2, strict:FALSE, regexes:__vcmp_regex_table__) < 0;
}

###
# Sorts lists of dotted version strings.
# See documentation on ver_compare in misc.func.
#
# @anonparam First the list to be sorted
# @param accessor Accessor function to use, defaults to identity
# @param regexes Array to be passed as the regexes parameter to misc_func's ver_compare
#
# @category collib
#
# @return a sorted list
##
function version_sort (accessor, regexes)
{
  __vcmp_regex_table__ = regexes;
  var ret = merge_sort(_FCT_ANON_ARGS[0], comparator:@_vcmp, accessor:accessor);
  __vcmp_regex_table__ = NULL;
  return ret;
}

function split_in_half()
{
  var list = _FCT_ANON_ARGS[0];
  var end = max_index(list) / 2;

  var results = make_list();
  results[0] = make_list();
  results[1] = make_list();

  var i;
  for (i = 0; i < end; i++)
  {
    results[0][max_index(results[0])] = list[i];
  }

  for (i = end; i < max_index(list); i++)
  {
    results[1][max_index(results[1])] = list[i];
  }

  return results;
}

function merge_sort_merge(accessor, comparator)
{
  var a = _FCT_ANON_ARGS[0];
  var b = _FCT_ANON_ARGS[1];
  if (isnull(accessor)) { accessor = @id; }
  if (isnull(comparator)) { comparator = @lt; }

  var index_a = 0;
  var index_b = 0;

  var result = make_list();
  var choose_a;

  while (index_a < max_index(a) || index_b < max_index(b))
  {
    if (index_a >= max_index(a))
      choose_a = FALSE;
    else if (index_b >= max_index(b))
      choose_a = TRUE;
    else if (comparator(accessor(b[index_b]), accessor(a[index_a])))
      choose_a = FALSE;
    else
      choose_a = TRUE;

    if (choose_a)
    {
      result[max_index(result)] = a[index_a];
      index_a++;
    }
    else
    {
      result[max_index(result)] = b[index_b];
      index_b++;
    }
  }
  return result;
}

##
# @param n   number of elements to take
# @anonparam list
# @return    list containing first n elements of list
##
function take (n)
{
  var list;
  list = _FCT_ANON_ARGS[0];
  if (isnull(n) || n == 0)
    return [];
  if (n >= max_index(list))
    return _FCT_ANON_ARGS[0];
  delete_element(endidx:max_index(list), idx:n, var:list);
  return list;
}

##
# @param n   number of elements to take
# @anonparam list
# @return    list omitting first n elements of list
##
function drop (n)
{
  var list;
  list = _FCT_ANON_ARGS[0];
  if (n == 0)
    return list;
  if (n >= max_index(list))
    return [];
  delete_element(endidx:n-1, idx:0, var:list);
  return list;
}

##
# @param from the first index of the sublist
# @param to   last index of sublist [optional]
# @anonparam list from which to extract sublist
# @return a sublist of the list provided, from the 'from' index
# (inclusive) to the 'to' index (exclusive)
##
function sublist (from, to)
{
  var list, end;
  list = _FCT_ANON_ARGS[0];
  if (from < 0) from = 0;
  if (to < 0) to = 0;
  if (isnull(to)) to = max_index(list);
  if (isnull(from)) from = 0;
  if (from <= 0 && to >= max_index(list)) return list;
  if (to - from <= 0) return [];
  list = drop(list, n:from);
  end = (to - from);
  if (end < max_index(list))
    return take(list, n:end);
  else
    return list;
}

##
# @anonparam 1st: an element
# @anonparam 2nd: list to push to
# @return NULL
# @remark
# Pushes the first parameter onto the end the list,
# altering the list in-place.
#
# Usage: every instance of the form
# list = make_list(list, new_element);
# should be replaced with the more efficient
# push(new_element, list);
##
function push ()
{
  insert_element(idx:max_index(_FCT_ANON_ARGS[1]),
                 value:_FCT_ANON_ARGS[0],
                 var:_FCT_ANON_ARGS[1]);
  return NULL;
}

##
# @anonparam list
# @return last element from list
# @remark
# Pops the last element off of a list, and returns that element.
# If the list is empty, pop() will throw an "Invalid index for
# array" error. Note that this function alters the list in-place.
##
function pop ()
{
  var x;
  if (equals([],_FCT_ANON_ARGS[0])) return NULL;
  x = _FCT_ANON_ARGS[0][max_index(_FCT_ANON_ARGS[0])-1];
  delete_element(endidx:max_index(_FCT_ANON_ARGS[0])-1,
                 idx:max_index(_FCT_ANON_ARGS[0])-1,
                 var:_FCT_ANON_ARGS[0]);
  return x;
}

##
# @param list
# @return the reversed image of that list.
##
function reverse ()
{
  var r, i;
  r = make_list();
  for (i = max_index(_FCT_ANON_ARGS[0])-1; i >= 0; i --)
    push(_FCT_ANON_ARGS[0][i], r);
  return r;
}

##
# @anonparam list
# @param f: dyadic function pointer (comparator)
# @return the most f element in the list, where f is a
# two-parameter boolean-returning comparator function pointer
# (like \@le, for example).
##
function most (f)
{
  var elem, acc;
  acc = NULL;
  var i, length = max_index(_FCT_ANON_ARGS[0]);
  for (i = 0; i < length; i++)
  {
    elem = _FCT_ANON_ARGS[0][i];
    if (isnull(acc) || f(elem, acc))
      acc = elem;
  }
  return acc;
}

##
# @anonparam list
# @param f function pointer (predicate)
# @param args additional arguments to pass to f
# @return TRUE if apply(f:f, args:args, x) == TRUE for all
# x in _FCT_ANON_ARGS[0], FALSE otherwise
##
function all (f, args)
{
  var m;
  m = map(f:f, args:args, _FCT_ANON_ARGS[0]);
  return reduce(f:@and, acc:TRUE, m);

}

##
# @param f, a predicate function pointer
# @param args additional arguments to pass to f
# @return TRUE if f(x) == TRUE for *some* x in _FCT_ANON_ARGS[0],
# and FALSE otherwise.
# @remark just an alias to contains
##
function any (f, args)
{
  var list;
  list = map(f:f, _FCT_ANON_ARGS[0]);
  return contains(args:args, list, TRUE);
}

##
# @anonparam list
# @return the maximum element of the list, under the > relation.
##
function max ()
{
  return most(f:@gt, _FCT_ANON_ARGS[0]);
}

##
# @anonparam list
# @return the minimum element of the list, under the < relation.
##
function min ()
{
  return most(f:@lt, _FCT_ANON_ARGS[0]);
}

##
# @anonparam a list of lists
# @return the length of the longest list in a list of lists.
##
function maxlength ()
{
  return max(map(f:@max_index, _FCT_ANON_ARGS[0]));
}

##
# @anonparam a list of lists
# @return the length of the shortest list in a list of lists
##
function minlength ()
{
  return min(map(f:@max_index, _FCT_ANON_ARGS[0]));
}

##
# @anonparam a list of strings
# @return the length of the longest string in a list of strings.
##
function maxstrlen ()
{
  return max(map(f:@strlen, _FCT_ANON_ARGS[0]));
}

##
# @anonparam a list of strings
# @return the length of the shortest string in a list of strings.
##
function minstrlen ()
{
  return min(map(f:@strlen, _FCT_ANON_ARGS[0]));
}

##
# @anonparam list #1
# @anonparam list #2
# @return an array formed by pairing keys from list #1 with values
# from list #2.
##
function array_zip ()
{
  var i, m, arr;
  m = minlength(_FCT_ANON_ARGS);
  arr = make_array();
  for (i = 0; i < m; i++)
  {
    arr[_FCT_ANON_ARGS[0][i]] = _FCT_ANON_ARGS[1][i];
  }
  return arr;
}

##
# @anonparam list #1
# @anonparam list #2
# @return a list of pairs, whose first elements are drawn from
# list #1, and whose second elements are drawn from list #2
##
function pair_zip ()
{
  var plist, i, m;
  m = minlength(_FCT_ANON_ARGS);
  plist = make_list();
  for (i = 0; i < m; i++)
  {
    push([_FCT_ANON_ARGS[0][i], _FCT_ANON_ARGS[1][i]], plist);
  }
  return plist;
}

##
# @anonparam list #1
# @anonparam list #2
# @param binary function pointer f
# @param args additional arguments to pass to f
# @return a list defined by {f(list1[i], list2[i]) | i under length of shortest list}
##
function zipwith (f, args)
{
  var i, m, lst;
  m = min(map(f:@max_index, _FCT_ANON_ARGS));
  lst = make_list();
  if (isnull(args)) args = [];
  for (i = 0; i < m; i++)
  {
    var val, ap_args = list_copy(args);
    push(_FCT_ANON_ARGS[0][i], ap_args);
    push(_FCT_ANON_ARGS[1][i], ap_args);
    val = apply(f:f, args:ap_args);
    push (val, lst);
  }
  return lst;
}

##
# @anonparam serializable data
# @remark A convenience function, mostly just for debugging this
# library. It serializes and prints data structures.
##
function show ()
{
  if (typeof_ex(_FCT_ANON_ARGS[0]) == 'set')
    return _FCT_ANON_ARGS[0].to_string();
  else
    return serialize(_FCT_ANON_ARGS[0]);
}

global_var __acc_table;
__acc_table = {'data':'', 'int':0, 'list':make_list()};

##
# @anonparam list
# @param f: function pointer to a binary function, whose return type
# is the same as its parameter types
# @param acc: the accumulator value, should be same type as return type.
# @return the result of succesively applying f to the result of f(x, acc)
# for each element x of the list.
# @remark Example: reduce(f:\@plus, acc:0, [1,2,3]) evaluates as follows:
# {noformat}
# 0 + _     | [1,2,3]
# 0 + 1 = 1 | [2,3]
# 1 + 2 = 3 | [3]
# 2 + 3 = 5 | []
# {noformat}
##
function reduce (f, acc, args)
{
  var i, list;
  list = _FCT_ANON_ARGS[0];
  if (isnull(acc))
    acc = __acc_table[typeof_ex(_FCT_ANON_ARGS[0][0])];

  for (i = 0; i < max_index(list); i++)
  {
    var args_p = list_copy(args);
    push(acc, args_p);
    push(list[i], args_p);
    acc = apply(f:f, args:args_p);
  }
  return acc;
}

##
# Determines if first anonymous argument < second anonymous argument when both as treated as CVEs
#
# @anonparam First CVE to compare
# @anonparam Second CVE to compare
#
# @return 1 if First doesn't meet CVE criteria or is lower in year than Second or same year and lower in ID than Second
#         else 0
##
function cve_comp ()
{
  local_var cve1 = _FCT_ANON_ARGS[0];
  local_var cve2 = _FCT_ANON_ARGS[1];
  # Basic comp function logic is return 1 if a < b.
  # If something broke, just return the broken one first.
  if (empty_or_null(cve1)) return 1;
  if (empty_or_null(cve2)) return 0;
  var cve1_split = split(cve1, sep:"-", keep:FALSE);
  var cve2_split = split(cve2, sep:"-", keep:FALSE);
  if (empty_or_null(cve1_split) || len(cve1_split) < 3) return 1;
  if (empty_or_null(cve2_split) || len(cve2_split) < 3) return 0;
  # Year
  if (int(cve1_split[1]) < int(cve2_split[1]))
  {
    return 1;
  }
  else if (int(cve1_split[1]) > int(cve2_split[1]))
  {
    return 0;
  }
  # ID
  if (int(cve1_split[2]) < int(cve2_split[2]))
  {
    return 1;
  }
  else if (int(cve1_split[2]) > int(cve2_split[2]))
  {
    return 0;
  }
  # Equal, doesn't matter either way
  return 0;
}

##
# Returns a sorted list of CVEs
#
# @anonparam list of CVEs to compare
#
# @return list sorted by CVE
#         or NULL if anonparam is empty or NULL
##
function cve_sort ()
{
  local_var seq = _FCT_ANON_ARGS[0];
  if (isnull(seq) || max_index(seq) < 1) return NULL;
  return merge_sort(seq, comparator:@cve_comp);
}

} # end namespace collib

