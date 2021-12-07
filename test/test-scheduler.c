#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "scheduler.h"

static void print_hello(void *data)
{
  fprintf(stderr, "Hello\n");
}

static void print_bye(void *data)
{
  fprintf(stderr, "Bye\n");
}

int main(void)
{
  struct task_s *task1 = task_init();
  struct task_s *task2 = task_init();
  /* star 2 seconds from now, and repeat every 1 seconds */
  task_start(task1, 2000, 1000, NULL, &print_hello);
  /* start immediately, and repeate every half seconds */
  task_start(task2, 0, 500, NULL, &print_bye);

  sleep(10);

  task_cleanup(task1);
  task_cleanup(task2);

  return EXIT_SUCCESS;
}
