-- rex-replay — a port of btrachey/wezterm-replay to Rex.
--
-- Parse the current pane's output, extract things you may want at the next
-- prompt (URLs, commands in `backticks`), pick one, and type it into the
-- pane without running it — exactly the wezterm plugin's behavior, with no
-- shell integration required.
--
-- Rex has no plugin manager yet, so installation is a git clone plus one
-- line in ~/.config/rex/init.lua:
--
--   dofile(os.getenv('HOME') .. '/.config/rex/plugins/rex-replay/plugin/init.lua')
--     .setup({ replay_key = 'l', recall_key = 'q' })
--
-- How the pieces map onto Rex:
--   wezterm semantic zones ("last Output")  -> terminal.format (text, trim,
--       unwrap) of the screen + scrollback, searched newest-first
--   wezterm.action InputSelector            -> rex.ui.pick in the palette
--   pane:send_text(cmd)                     -> terminal.write (no newline)
--   wezterm.log_info                        -> rex.log
--   ~/.replay.wez/cache.json                -> $XDG_CACHE_HOME/rex-replay/cache.json
--
-- Deliberate differences from the wezterm plugin:
-- * No shell integration. Rex exposes no semantic zones and shell-specific
--   OSC markers are off-limits, so there is no "previous command's output"
--   zone; instead the whole capture is searched and matches are ordered by
--   position from the bottom, so the freshest ones come first. Matches from
--   long-ago scrollback sink to the end of the list; the pick field filters.
-- * Backtick matching is per-line and non-greedy: "run `a` and `b`" yields
--   two items, not one blob spanning both (the plugin's greedy pattern bug).
-- * Trailing punctuation is stripped from URLs, and duplicate matches are
--   dropped, so a bare "https://x)" inside parens doesn't list twice.
-- * A single extraction is cached too, so recall still offers it (the plugin
--   only cached when the picker appeared).

-- Make the plugin's modules requirable from anywhere: find this file's
-- directory, put it on package.path, and drop cached copies so a config
-- reload re-reads the module tree after a git pull.
local here = debug.getinfo(1, 'S').source
here = here:gsub('^@', ''):match('^(.*)/[^/]*$') or '.'
local modpath = here .. '/?.lua'
if not package.path:find(modpath, 1, true) then
  package.path = modpath .. ';' .. package.path
end
for name in pairs(package.loaded) do
  if type(name) == 'string' and name:find('^rex_replay%.') then
    package.loaded[name] = nil
  end
end

local util = require('rex_replay.util')
local extractors = require('rex_replay.extractors')
local summarizer = require('rex_replay.summarizer')
local actions = require('rex_replay.actions')

local function setup(opts)
  opts = opts or {}
  for idx, ex in ipairs(opts.extractors or {}) do
    extractors.validate(ex, idx)
  end
  -- custom first, then the plugin's defaults, like the wezterm config merge
  extractors.set_extractors(opts.extractors)
  summarizer.configure(opts.summarize)
  actions.register_actions()

  if opts.skip_keybinds then
    util.log_info('skipping auto-setting of key bindings')
    return
  end
  local prefix = opts.prefix_key or 'ctrl+b'
  rex.bind(prefix .. '>' .. (opts.replay_key or 'l'), 'replay_command')
  rex.bind(prefix .. '>' .. (opts.recall_key or 'q'), 'replay_recall')
end

return {
  setup = setup,
  -- Direct entry points for scripts (`rex do`) and other actions. They show
  -- rex.ui.pick, so only call them from an action's run or a script — a
  -- key-bound function makes the picker silently fail. Key bindings should
  -- name the actions: 'replay_command' / 'replay_recall'.
  replay = actions.replay_command,
  recall = actions.replay_recall,
  -- internals, exposed for testing from a `rex do` script
  _capture_text = require('rex_replay.capture').capture_text,
  _extract_all = extractors.extract_all,
  _cache_path = util.cache_path,
  _tail_bytes = util.tail_bytes,
}
