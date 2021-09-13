<div align="center">
  <br />
  <p>
    <a href="https://cee-studio.github.io/orca"><img src="https://raw.githubusercontent.com/cee-studio/orca-docs/master/docs/source/images/logo.svg" width="546" alt="orca" style="background-color:red;" /></a>
  </p>
  <br />
  <p>
    Easy to reason, easy to debug, easy to use.
  </p>
  <p>
    Join our Discord server: <a href="https://discord.gg/2jfycwXVM3"><img src="https://img.shields.io/discord/562694099887587338?color=5865F2&logo=discord&logoColor=white" alt="Discord server" /></a>
  </p>
</div>

## About

Orca is implemented in plain C, its symbols are organized to be easily matched to the documentation of the API being covered.

This is done in order to:
* Reduce the need of thoroughly documenting every Orca API
* Reduce our user's cognitive burden of having to read both Orca API documentation and supported REST API documentations. 
* The codebase becomes easier to navigate.

Orca's implementation has minimum external dependencies to make bot deployment deadly simple.

### Design

- Easy to reason about the code: we use the most native data structures,
   the simplest algorithms, and intuitive interfaces.

- Easy to debug (networking and logic) errors: extensive assertion 
  and logging facilities.

- Easy to use for the end users: we provide internal synchronization
  so that the user may provide scalability to his applications without
  having to excessively worry about race-conditions. All transfers made
  with Orca are thread-safe by nature.

### Minimal example

```c
#include <string.h> // strcmp()
#include <orca/discord.h>

void on_ready(
  struct discord *client, 
  const struct discord_user *bot) 
{
  log_info("Logged in as %s!", bot->username);
}

void on_message(
  struct discord *client, 
  const struct discord_user *bot, 
  const struct discord_message *msg)
{
  // if message content equals "ping", then reply with "pong"
  if (0 == strcmp(msg->content, "ping")) {
    struct discord_create_message_params params = { .content = "pong" };
    discord_create_message(client, msg->channel_id, &params, NULL);
  }
}

int main() {
  struct discord *client = discord_init(BOT_TOKEN);
  discord_set_on_ready(client, &on_ready);
  discord_set_on_message_create(client, &on_message);
  discord_run(client);
}
```
*This is a minimalistic example, refer to `examples/` for a better overview.*

## Build Instructions

### On Windows

* Install WSL2 and get either Ubuntu or Debian [here](https://docs.microsoft.com/en-us/windows/wsl/install-win10).
* **Make sure you are in your Linux $HOME folder before proceeding!**
* Continue on to [On Linux](#on-linux) and follow your distro's building steps.

### On Linux

The only dependencies are `curl-7.64.0` or higher built with OpenSSL, and `wget` that will 
be used by the Makefile for fetching [cee-utils](https://github.com/cee-studio/cee-utils) files.

#### Ubuntu and Debian

```bash
$ sudo apt-get install -y build-essential wget
$ sudo apt-get install -y libcurl4-openssl-dev libssl-dev
```

#### Void Linux

```bash
$ sudo xbps-install -S wget
$ sudo xbps-install -S libcurl-devel
```
### Setting up your environment

#### Clone orca into your workspace

```bash
$ git clone https://github.com/cee-studio/orca.git
$ cd orca
```

#### Compile orca

```bash
$ make
```

### Configuring orca

The following outlines the default fields of `config.json`
```js
{
  "logging": { // logging directives
    "level": "trace",        // trace, debug, info, warn, error, fatal
    "filename": "bot.log",   // the output file
    "quiet": false,          // change to true to disable logs in console
    "overwrite": false,      // overwrite existing file with "filename"
    "use_color": true,       // log with color
    "http": {
      "enable": true,        // generate http specific logging
      "filename": "http.log" // the output file
    },
    "disable_modules": ["WEBSOCKETS", "USER_AGENT"] // disable logging for these modules
  },
  ...         // API directives (discord, slack, github, etc)
}
```

### Test Echo-Bot

1. Get your bot token and add it to `config.json`, 
   by assigning it to discord's "token" field. There are 
   well written instructions from the 
   [discord-irc](https://github.com/reactiflux/discord-irc/wiki/Creating-a-discord-bot-&-getting-a-token)
   about how to get your bot token and adding it to a server.
2. Run `make examples`
3. Go to the `examples/` folder and run `./bot-echo.out`

#### Get Echo-Bot Response

Type a message in any channel the bot has access to, the bot should echo it.

#### Terminate Echo-Bot

With `Ctrl-C` or by closing the Terminal.

### Create your first bot

* Head to `my_bot/`, a special folder set-up for your convenience. There you will also find a preset `Makefile` and `myBot.c` that can be edited at will.
* Read our guide on how to [build your first bot](docs/BUILDING_A_BOT.md).

## Installing orca

In case the `my_bot/` folder doesn't cut the cake, its possible to install orca as follows:
```bash
$ sudo make install
```

Installed headers must be prefixed with `orca/` like so:
```c
#include <orca/discord.h>
#include <orca/github.h>
```

## Debugging Memory Errors

* The recommended method: 
  Use [SaiphC](docs/SAIPHC.md) to build your bot and run the generated executable. All runtime memory errors will be reported. 

* The convenient method:
  Using valgrind which cannot report all runtime memory errors. 
```bash
$ valgrind ./myBot.out
```

## Links

- [Documentation](https://cee-studio.github.io/orca/)
- [Create your first bot](docs/BUILDING_A_BOT.md)
- [Contributing](docs/CONTRIBUTING.md)
- [Discord Server](https://discord.gg/2jfycwXVM3)
- [Debbuging with SaiphC](docs/SAIPHC.md)

## Contributing
Check our [Contributing Guidelines](docs/CONTRIBUTING.md) to get started! If you are here for the Discord API, please check our [Discord API Roadmap](docs/DISCORD_ROADMAP.md).

**Give us a star if you like this project!**
