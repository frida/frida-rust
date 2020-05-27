#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int
main (int argc, char * argv[])
{
  printf ("Victim running with PID %d\n", getpid ());

  while (1)
  {
    int fd;

    fd = open ("/etc/hosts", O_RDONLY);
    if (fd != -1)
      close (fd);

    fd = open ("/etc/passwd", O_RDONLY);
    if (fd != -1)
      close (fd);

    sleep (1);
  }
}
