/*
 * A bot that lists public gists in JSON form.
*/

#include <stdio.h>
#include <orca/github.h>

void print_usage()
{
    printf("bot-github-public-gists - create gists from the terminal\n");
    printf("Usage: bot-github-public-gists.exe\n\n");
}

int main(int argc, char *argv[])
{
    struct github *client = github_config_init("bot.config", NULL);

    if (argc == 1) {
        print_usage();
        exit(1);
    }
    else if (argc > 1) {
        printf("bot-github-public-gist expects 0 arguments.\n");
        exit(1);
    }

    struct github_list_public_gists_params params = {.page = 0, .per_page = 30};

    return 0;
}

