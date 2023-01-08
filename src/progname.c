#include <pound.h>
#include <string.h>

char const *progname;

void
set_progname (char const *arg)
{
  if ((progname = strrchr (arg, '/')) == NULL)
    progname = arg;
  else
    progname++;
}

static int copyright_year = 2022;

#define VALUE_COLUMN 28

static void
print_string_values (struct string_value *values, FILE *fp)
{
  struct string_value *p;
  char const *val;

  for (p = values; p->kw; p++)
    {
      int n = fprintf (fp, "%s:", p->kw);
      if (n < VALUE_COLUMN)
	fprintf (fp, "%*s", VALUE_COLUMN-n, "");

      switch (p->type)
	{
	case STRING_CONSTANT:
	  val = p->data.s_const;
	  break;

	case STRING_INT:
	  fprintf (fp, "%d\n", p->data.s_int);
	  continue;

	case STRING_VARIABLE:
	  val = *p->data.s_var;
	  break;

	case STRING_FUNCTION:
	  val = p->data.s_func ();
	  break;

	case STRING_PRINTER:
	  p->data.s_print (fp);
	  fputc ('\n', fp);
	  continue;
	}

      fprintf (fp, "%s\n", val);
    }
}

void
print_version (struct string_value *settings)
{
  printf ("%s (%s) %s\n", progname, PACKAGE_NAME, PACKAGE_VERSION);
  printf ("Copyright (C) 2002-2010 Apsis GmbH\n");
  printf ("Copyright (C) 2018-%d Sergey Poznyakoff\n", copyright_year);
  printf ("\
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n\
This is free software: you are free to change and redistribute it.\n\
There is NO WARRANTY, to the extent permitted by law.\n\
");
  if (settings)
    {
      printf ("\nBuilt-in defaults:\n\n");
      print_string_values (settings, stdout);
    }
}

