//
// Created by lothar on 06/02/2021.
//

#include "../json-scanf.h"
#include <stdio.h>
#include <stdlib.h>
#include "../jsmn.h"
#include "../ntl.h"
#include <string.h>
#include "../libdiscord.h"

using namespace discord;

#if 0
static char * print_token(jsmntype_t t) {
  switch(t) {
    case JSMN_UNDEFINED: return "undefined";
    case JSMN_OBJECT: return "object";
    case JSMN_ARRAY: return "array";
    case JSMN_STRING: return "string";
    case JSMN_PRIMITIVE: return "primitive";
  }
}
#endif

char test_string [] =
        "{\n"
        "|channel|: [\""
        "{\n"
            "|id|: |41771983423143937|,\n"
            "|guild_id|: |41771983423143937|,\n"
            "|name|: |general|,\n"
            "|type|: 0,\n"
            "|position|: 6,\n"
            "|permission_overwrites|: [],\n"
            "|rate_limit_per_user|: 2,\n"
            "|nsfw|: true,\n"
            "|topic|: |24/7 chat about how to gank Mike #2|,\n"
            "|last_message_id|: |155117677105512449|,\n"
            "|parent_id|: |399942396007890945|\n"
            "}\n"
            "]\n"
        "}";

struct channel {
    uint64_t id;
    int type;
    uint64_t guild_id;
    int position;
    char name;
    char topic;
    bool nsfw;
    uint64_t last_message_id;
    int bitrate;
    int user_limit;
    int rate_limit_per_user;
    user::dati **recipients;
    char icon;
    uint64_t owner_id;
    uint64_t application_id;
    uint64_t parent_id;
    int64_t last_pin_timestamp;
    discord::channel::message::dati **messages;
};

void load_tree_node (char * str, size_t len, void * p) {
    struct channel * channel = (struct channel *)p;
    json_scanf(str, len,
               "[id]%F"
               "[type]%d"
               "[guild_id]%F"
               "[position]%d"
               "[name]%s"
               "[topic]%s"
               "[nfsw]%d"
               "[last_message_id]%F"
               "[bitrate]%d"
               "[user_limit]%d"
               "[rate_limit_per_user]%d"
               "[recipients]%p"
               "[icon]%s"
               "[owner_id]%F"
               "[application_id]%F"
               "[parent_id]%F"
               "[last_pin_timestamp]%F"
               "[messages]%F",
               &channel->id,
               &channel->type,
               &channel->guild_id,
               &channel->position,
               channel->name,
               channel->topic,
               &channel->nsfw,
               &channel->last_message_id,
               &channel->bitrate,
               &channel->user_limit,
               &channel->rate_limit_per_user,
               &user::json_list_load, &channel->recipients,
               channel->icon,
               &channel->owner_id,
               &channel->application_id,
               &channel->parent_id,
               &channel->last_pin_timestamp,
               &discord::channel::message::json_list_load, &channel->messages);
}
static int
print_array (char * str, size_t len, void * p)
{
    struct channel * channel = (struct channel *)p;

    return json_snprintf(str, len,
                         "{"
                         "|id|:%d,"
                         "|type|:%d,"
                         "|guild_id|:%F,"
                         "|position|:%d,"
                         "|name|:%s,"
                         "|topic|:%s"
                         "|nsfw|:%s"
                         "|last_message_id|:%F"
                         "|bitrate|:%d"
                         "|user_limit|:%d"
                         "|rate_limit_per_user|:%d"
                         "|recipients|:%p"
                         "|icon|:%s"
                         "|owner_id|:%F"
                         "|application_id|:%F"
                         "|parent_id|:%F"
                         "|last_pin_timestamp|:%F"
                         "|messages|:%F"
                         "}",
                         channel->id,
                         channel->type,
                         channel->guild_id,
                         channel->position,
                         channel->name,
                         channel->topic,
                         channel->nsfw,
                         channel->last_message_id,
                         channel->bitrate,
                         channel->user_limit,
                         channel->rate_limit_per_user,
                         &channel->recipients,
                         channel->icon,
                         channel->owner_id,
                         channel->application_id,
                         channel->parent_id,
                         channel->last_pin_timestamp,
                         channel->messages);
}

static int
print_all (char * str, size_t len, void * p)
{
    return ntl_sn2str(str, len, (void **)p, NULL, print_array);
}

int main ()
{
    char tx [] = {'1', '2', '3', '\n', '\0'};
    size_t x = 0;
    char * yx = json_escape_string(&x, tx, 4);
    fprintf(stderr, "%.*s\n", x, yx);

    char * json_str = NULL;
    int s = json_asprintf(&json_str, test_string);
    //printf("%s\n", json_str);
    struct sized_buffer array_tok = { .start = NULL, .size = 0 };
    json_scanf(json_str, s, "[channel]%T", &array_tok);
    printf ("json_array_string:\n%.*s\n", array_tok.size, array_tok.start);

    jsmn_parser parser;
    jsmn_init(&parser);
    jsmntok_t * t = NULL;
    int num_tok = jsmn_parse(&parser, array_tok.start, array_tok.size, NULL, 0);
    //printf ("%d\n", num_tok);

    t = (jsmntok *)malloc(sizeof(jsmntok_t) * num_tok);
    jsmn_init(&parser);
    num_tok = jsmn_parse(&parser, array_tok.start, array_tok.size, t, num_tok+1);

    int i;

    printf ("test []%%L\n");
    struct sized_buffer ** tokens = NULL;
    json_scanf(array_tok.start, array_tok.size, "[tree]%L", &tokens);
    if (tokens != NULL) {
        for (i = 0; tokens[i]; i++) {
            printf("token [%p, %zu]\n", tokens[i]->start, tokens[i]->size);
            printf("token %.*s\n", tokens[i]->size, tokens[i]->start);
        }
    }
    free(tokens);

    printf ("test [channel]%%L\n");
    tokens = NULL;
    json_scanf(json_str, s, "[channel]%L", &tokens);
    struct channel ** nodes =
            (struct channel **) ntl_fmap((void **)tokens, sizeof(struct channel), NULL);
    for (i = 0; tokens[i]; i++) {
        printf ("token [%p, %d]\n", tokens[i]->start, tokens[i]->size);
        printf ("token %.*s\n", tokens[i]->size, tokens[i]->start);
        load_tree_node(tokens[i]->start, tokens[i]->size, nodes[i]);
    }

    int wsize;
    char buf[1024];
    json_snprintf(buf, 1024, "{|a|:%d}", 10);
    fprintf (stderr, "%s\n", buf);

    json_snprintf(buf, 1024, "{|a|:%b}", true);
    fprintf (stderr, "%s\n", buf);

    json_snprintf(buf, 1024, "{|a|:%b}", false);
    fprintf (stderr, "%s\n", buf);

    json_snprintf(buf, 1024, "{|a|:%S}", NULL);
    fprintf (stderr, "%s\n", buf);

    json_snprintf(buf, 1024, "{|a|:%S}", "abc");
    fprintf (stderr, "%s\n", buf);

    json_snprintf(buf, 1024, "{|a|:|%s|}", "abc");
    fprintf (stderr, "%s\n", buf);

    json_snprintf(buf, 1024, "{|a|:|%.*s|}", 4, tx);
    fprintf (stderr, "%s\n", buf);

    json_snprintf(buf, 1024, "{|a|:%.*S}", 4, tx);
    fprintf (stderr, "%s\n", buf);

    wsize = json_snprintf(NULL, 0, "{|a|:|%s|, |b|:%d, |x|:%F }", "abc",
                          10, print_all, nodes);
    fprintf (stderr, "%d\n", wsize);

    wsize++;
    char * b = (char*)malloc(wsize);

    fprintf (stderr, "test json_snprintf\n");
    wsize = json_snprintf(b, wsize, "{|a|:|%s|, |b|:%d, |x|:%F }", "abc",
                          10, print_all, nodes);
    fprintf (stderr, "%d %s\n", wsize, b);

    fprintf(stderr, "test json_asprintf\n");
    wsize = json_asprintf(&b, "{|a|:|%s|, |b|:%d, |x|:%F }", "abc",
                          10, print_all, nodes);
    fprintf (stderr, "%d %s\n", wsize, b);

    return 0;
}


