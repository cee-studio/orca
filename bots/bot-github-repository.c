/*
 * A bot that retrieves information about a repository.
*/

#include <stdio.h>
#include <orca/github.h>

int main() {
    struct github* client = github_config_init("bot.config", NULL);

    char payload[4096] = {0};

    github_get_repository(client, "antropez", "orca", payload);

}
