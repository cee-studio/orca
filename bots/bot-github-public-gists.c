/*
 * A bot that lists public gists in JSON form.
*/
#include <stdio.h>
#include "github.h"
void print_usage()
{
    printf("bot-github-public-gists - create gists from the terminal\n");
    printf("Usage: bot-github-public-gists.exe\n\n");
}
int main(int argc, char *argv[])
{
    struct github *client = github_config_init("bot.config", NULL);
    if (argc > 1) {
        print_usage();
        exit(1);
    }
    struct sized_buffer buffer;
    struct github_list_public_gists_params params = {.page = 0, .per_page = 30, .since = ""};
    github_list_public_gists(client, &params, &buffer);
    printf("%s\n", buffer.start);
    return 0;
}
