# Rex Replay

Parse the output of commands and extract useful information you may want to
have pasted into your next command prompt. A common example is the output of
`git push`. If your remote forge sends back a URL for opening a pull request,
this plugin will parse that URL, automatically prepend `open`, and paste the
full result into your next command line, e.g.

``` bash
$ git push
Enumerating objects: 5, done.
...
remote: Create a pull request for 'branch-name' on GitHub by visiting:
remote:      https://github.com/org/repo/pull/new/branch-name
remote:
To https://github.com/org/repo.git
 * [new branch]          branch-name -> branch-name

$ <trigger plugin here>
$ open https://github.com/org/repo/pull/new/branch-name
```

By default, the plugin binds `ctrl+b>l` ("last output") and `ctrl+b>q`
("queue") under a tmux-style prefix.

A port of [btrachey/wezterm-replay](https://github.com/btrachey/wezterm-replay)
to [Rex](https://www.superlogical.com/rex/). It needs **no shell
integration**: unlike the WezTerm plugin, which reads semantic zones, this
one captures the pane's screen + scrollback through Rex's terminal block API
(`com.superlogical.terminal.format`, paged via `blob_read`) and searches it
newest-first.

## Install

Rex has no official plugin manager yet, so install is a git clone plus one
line in `~/.config/rex/init.lua` (the same file as your keybindings; it can
live beside them on any machine the Rex server runs on):

```sh
mkdir -p ~/.config/rex/plugins
git clone https://github.com/btrachey/rex-replay ~/.config/rex/plugins/rex-replay
```

Then add to `init.lua`:

```lua
dofile(os.getenv('HOME') .. '/.config/rex/plugins/rex-replay/plugin/init.lua')
  .setup()
```

Reload the configuration:

```sh
rex config reload
```

`setup()` is load-time only (it registers actions and bindings), so the
usual `rex config reload` picks up everything, including code updates after
a `git pull` — the loader drops cached copies of its own modules first.

## Customizing

Change the trigger keys (they are bound under `prefix_key`):

```lua
local replay = dofile(os.getenv('HOME') .. '/.config/rex/plugins/rex-replay/plugin/init.lua')
replay.setup({
  prefix_key = 'ctrl+b',  -- the prefix; default 'ctrl+b'
  replay_key = 'l',       -- capture + extract + pick; default 'l'
  recall_key = 'q',       -- re-open the last extraction's list; default 'q'
})
```

### Custom Extractors

The following extractors are built-in:

* Commands inside backtick spans
* URLs, bracketed forms first, with trailing punctuation stripped and an
  `open` prefix

Extractors take the format of

```lua
{
  label = 'my_custom_extractor',  -- shown as the item's subtitle in the picker
  icon = 'globe',                 -- optional rex.ui.pick icon name
  prefix = 'prefix_string',       -- prepended to the match, with a space
  postfix = 'postfix_string',     -- appended to the match, with a space
  pattern = 'ABC%-%d+',           -- a Lua pattern; capture group 1 is the match
}
```

or, when a pattern is not enough,

```lua
{
  label = 'numbers_only',
  extractor = function(s)
    local matches = {}
    for m in string.gmatch(s, '%d%d+') do
      table.insert(matches, m)
    end
    return matches -- string[]
  end,
}
```

`pattern` and `extractor` are mutually exclusive. Add them under `extractors
=`; custom extractors are consulted first, so their items rank above the
defaults at equal position:

```lua
replay.setup({
  extractors = {
    { label = 'tickets', prefix = 'jira view', pattern = 'ABC%-%d+' },
  },
})
```

### Full Customization

`skip_keybinds` keeps the plugin from binding anything; bind the action
names yourself. Bind by name, not by a Lua function: `rex.ui.pick` only
works inside an action's `run`, so a key-bound wrapper function would make
the picker silently fail.

```lua
local replay = dofile(os.getenv('HOME') .. '/.config/rex/plugins/rex-replay/plugin/init.lua')
replay.setup({ skip_keybinds = true })
rex.bind('ctrl+alt+r', 'replay_command')
rex.bind('ctrl+alt+k', 'replay_recall')
```

The actions are registered as `replay_command` and `replay_recall`, so they
also appear in the command palette and can run with
`rex do replay_command -s SESSION -b BLOCK`.

The module also returns `replay.replay(ctx)` and `replay.recall(ctx)` for
driving the flow from scripts (`rex do`) or other actions. They show the
picker, so — same rule as above — call them only from an action's `run` or a
script, never from a key-bound function.

## Recall

If the extractors match more than one text segment, you get Rex's command
palette to choose from (type to filter). The list stays cached — in
`$XDG_CACHE_HOME/rex-replay/cache.json` — so `ctrl+b>q` can offer the other
matches again after you used the first one, until the next replay replaces
the cache. Like the WezTerm plugin, a list of exactly one match is typed
straight to the prompt without asking.

## How it differs from the WezTerm plugin

* **No shell integration required.** There are no semantic zones in Rex, so
  the plugin scans the newest ~128 KiB of screen + scrollback and orders
  matches by position from the bottom: the freshest come first, ancient
  scrollback sinks to the end (the filter box tames long lists). The WezTerm
  plugin only ever saw the previous command's output zone.
* Backtick matching is per-line and non-greedy, so ``run `a` and `b` ``
  yields two items instead of one blob spanning both.
* URLs are deduplicated and stripped of trailing punctuation.
* Actions are prefixed (`replay_command`/`replay_recall`) because Rex's
  action palette and `rex do` share one flat namespace.

## Development

The suite stubs the `rex` global and drives capture, extraction, the picker
paths, and the recall cache:

```sh
lua test/replay_test.lua
```

Rex embeds Lua 5.1; the module sticks to 5.1 spellings (`f:read('*a')`, no
`os.execute`/`io.popen` — use `rex.exec`). The suite runs on any lua ≥ 5.1.

Layout mirrors the WezTerm plugin:

```
plugin/init.lua            loader + setup()
plugin/rex_replay/
  capture.lua              terminal.format + blob_read paging
  extractors.lua           built-ins, validation, newest-first ranking
  actions.lua              replay_command / replay_recall
  util.lua                 logging, UTF-8-safe tail cut, recall cache
test/replay_test.lua       stubbed-rex suite
```

## License

MIT
