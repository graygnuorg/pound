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
