-- rex-replay test suite. Run from anywhere with plain lua (5.1 or newer;
-- the module sticks to Rex's embedded 5.1 spellings):
--
--   lua test/replay_test.lua
--
-- Rex's `rex` global is stubbed below; capture/pick/write paths are driven
-- against scripted fakes. The picker can't be tested live (rex.ui.pick fans
-- out to every connected app), so this suite is its regression net.

local root = arg[0]:match('^(.*)/[^/]*$') or '.'
package.path = root .. '/../plugin/?.lua;' .. package.path

-- Isolation guard: if the cache-dir override below ever regresses, fixture
-- lists must never leak into the real $XDG_CACHE_HOME/rex-replay/cache.json
-- that a live replay_recall would auto-type. Snapshot it up front; the last
-- case asserts it is untouched and restores it on failure.
local real_cache_path
do
  local dir = os.getenv('XDG_CACHE_HOME')
  if dir == nil or dir == '' then
    dir = (os.getenv('HOME') or '.') .. '/.cache'
  end
  real_cache_path = dir .. '/rex-replay/cache.json'
end
local function slurp(path)
  local f = io.open(path, 'r')
  if f == nil then
    return nil
  end
  local raw = f:read('*a')
  f:close()
  return raw
end
local cache_snapshot = slurp(real_cache_path)

-- ── minimal JSON (encode/decode of the shapes the cache uses) ────────────
local function json_stub()
  local M = {}
  local function esc(s)
    return (
      s:gsub('[%c"\\]', function(c)
        if c == '"' then
          return '\\"'
        elseif c == '\\' then
          return '\\\\'
        end
        local map = { ['\n'] = '\\n', ['\r'] = '\\r', ['\t'] = '\\t' }
        return map[c] or string.format('\\u%04x', c:byte())
      end)
    )
  end
  function M.encode(v)
    if type(v) == 'string' then
      return '"' .. esc(v) .. '"'
    end
    if type(v) == 'number' or type(v) == 'boolean' then
      return tostring(v)
    end
    if type(v) == 'table' then
      if #v > 0 or next(v) == nil then
        local parts = {}
        for _, x in ipairs(v) do
          parts[#parts + 1] = M.encode(x)
        end
        return '[' .. table.concat(parts, ',') .. ']'
      end
      local parts = {}
      for k, x in pairs(v) do
        parts[#parts + 1] = '"' .. esc(tostring(k)) .. '":' .. M.encode(x)
      end
      return '{' .. table.concat(parts, ',') .. '}'
    end
  end
  function M.decode(s)
    local pos = 1
    local function ws()
      pos = s:find('[^ \t\r\n]', pos) or (#s + 1)
    end
    local parse
    parse = function()
      ws()
      local c = s:sub(pos, pos)
      if c == '{' then
        local t = {}
        pos = pos + 1
        ws()
        if s:sub(pos, pos) == '}' then
          pos = pos + 1
          return t
        end
        while true do
          ws()
          local k = parse()
          ws()
          pos = pos + 1
          t[k] = parse()
          ws()
          local d = s:sub(pos, pos)
          pos = pos + 1
          if d == '}' then
            return t
          end
        end
      elseif c == '[' then
        local t = {}
        pos = pos + 1
        ws()
        if s:sub(pos, pos) == ']' then
          pos = pos + 1
          return t
        end
        while true do
          t[#t + 1] = parse()
          ws()
          local d = s:sub(pos, pos)
          pos = pos + 1
          if d == ']' then
            return t
          end
        end
      elseif c == '"' then
        pos = pos + 1
        local out = {}
        while true do
          local ch = s:sub(pos, pos)
          if ch == '\\' then
            out[#out + 1] = s:sub(pos, pos + 1)
            pos = pos + 2
          elseif ch == '"' then
            pos = pos + 1
            break
          else
            out[#out + 1] = ch
            pos = pos + 1
          end
        end
        return (table.concat(out):gsub('\\n', '\n'):gsub('\\"', '"'):gsub('\\\\', '\\'))
      elseif c == 't' then
        pos = pos + 4
        return true
      elseif c == 'f' then
        pos = pos + 5
        return false
      elseif c == 'n' then
        pos = pos + 4
        return nil
      else
        local e = s:find('[^%-%.%d]', pos) or (#s + 1)
        local n = tonumber(s:sub(pos, e - 1))
        pos = e
        return n
      end
    end
    return parse()
  end
  return M
end

-- ── rex stub ──────────────────────────────────────────────────────────────
local actions, picks_shown, written, logged = {}, {}, {}, {}
local fake_output = ''
local blob, blob_page, fail_after, read_calls
-- scripted fm backend; the summarizer's rex.exec branch reads this
local fm = { calls = {}, mode = nil, stdout = '', responds_total = 0 }
local function fm_reset(stdout, mode)
  fm.calls, fm.mode, fm.stdout = {}, mode, stdout
end

rex = {
  log = function(lvl, msg)
    logged[#logged + 1] = lvl .. ' ' .. msg
  end,
  bind = function(k, a)
    logged[#logged + 1] = 'bind ' .. k .. ' ' .. tostring(a)
  end,
  action = function(def)
    actions[def.name] = def
  end,
  json = json_stub(),
  exec = function(argv, opts)
    if argv[1] == 'fm' then -- scripted summarizer backend
      fm.calls[#fm.calls + 1] = argv
      fm.last_opts = opts or {}
      if fm.mode == 'absent' then
        return nil, 'not_found'
      end
      if argv[2] == '--help' then
        return { ok = true, code = 0, stdout = '', stderr = '' } -- probe
      end
      fm.responds_total = fm.responds_total + 1
      if fm.mode == 'fail' then
        return { ok = false, code = 1, stdout = '', stderr = 'boom' }
      end
      if fm.mode == 'timeout' then
        return { ok = false, timed_out = true, code = -1, signal = 'SIGTERM', stdout = '', stderr = '' }
      end
      return { ok = true, code = 0, stdout = fm.stdout or '', stderr = '' }
    end
    os.execute("mkdir -p '" .. argv[3] .. "'")
    return { ok = true }
  end,
  ui = {
    pick = function(opts)
      return nil, 'cancelled'
    end,
  },
  block = {
    call = function(_, method, args)
      if method == 'write' then
        written[#written + 1] = args.data
        return { bytes_written = #args.data }
      end
      if fake_output == 'CAPTURE_FAIL' then
        return nil, 'not_found'
      end
      if method == 'format' then
        if blob then -- blob server mode
          if args.max_bytes == nil then
            if #blob > 983040 then
              return nil, 'too_large'
            end
            return { content = blob }
          end
          return { content = blob:sub(1, math.min(#blob, args.max_bytes)), id = 7, total = #blob }
        end
        return { content = fake_output }
      elseif method == 'blob_read' then
        read_calls = read_calls + 1
        if fail_after and read_calls > fail_after then
          return nil, 'not_found'
        end
        local start = args.offset + 1
        if start > #blob then
          return { data = '', eof = false, id = args.id, total = #blob }
        end
        local stop = math.min(start + blob_page - 1, #blob)
        return { data = blob:sub(start, stop), eof = stop >= #blob, id = args.id, total = #blob }
      end
      error('unexpected ' .. method)
    end,
  },
}

-- ── load the plugin like init.lua does ───────────────────────────────────
-- Each dofile re-runs the loader and re-initializes the modules (dropping
-- cached copies, like a config reload), so the cache-dir override must be
-- re-applied to the fresh util instance every time.
local CACHE_DIR = '/tmp/rex-replay-test-cache'
local function load_plugin()
  local m = dofile(root .. '/../plugin/init.lua')
  require('rex_replay.util')._set_cache_dir(CACHE_DIR)
  return m
end

local replay = load_plugin()
replay.setup { skip_keybinds = true }

-- ── helpers ───────────────────────────────────────────────────────────────
local function ids(items)
  local out = {}
  for _, it in ipairs(items) do
    out[#out + 1] = it.id
  end
  return out
end

local function check(name, got, want)
  local g, w = table.concat(got, '|'), table.concat(want, '|')
  if g ~= w then
    print('FAIL ' .. name .. '\n  got:  ' .. g .. '\n  want: ' .. w)
    os.exit(1)
  end
  print('ok   ' .. name)
end

-- ── extraction ────────────────────────────────────────────────────────────
check(
  'git push urls newest first',
  ids(replay._extract_all('PR https://git.test/pr/new\nTo https://git.test/repo.git')),
  { 'open https://git.test/repo.git', 'open https://git.test/pr/new' }
)

check(
  'two backticks non-greedy, newest first',
  ids(replay._extract_all('run `git commit` then `npm test`')),
  { 'npm test', 'git commit' }
)

local g =
  ids(replay._extract_all('(https://a.test/x). [https://b.test/y]; <https://c.test/z> bare https://d.test/w, end'))
for _, want in ipairs {
  'open https://a.test/x',
  'open https://b.test/y',
  'open https://c.test/z',
  'open https://d.test/w',
} do
  local found = false
  for _, x in ipairs(g) do
    if x == want then
      found = true
    end
  end
  assert(found, 'missing ' .. want .. ' in ' .. table.concat(g, '|'))
end
print('ok   url bracket forms + punctuation')

check(
  'dup url ranked by later occurrence',
  ids(replay._extract_all('https://old.test/x\nfiller line here\nhttps://new.test/y\nhttps://old.test/x again')),
  { 'open https://old.test/x', 'open https://new.test/y' }
)

check(
  'dedup keeps one entry',
  ids(replay._extract_all('https://x.test/a and https://x.test/a again')),
  { 'open https://x.test/a' }
)
check('backticks never span lines', ids(replay._extract_all('a `line\nbreaks` here')), {})
check('empty output', ids(replay._extract_all('')), {})
check('unbalanced backtick', ids(replay._extract_all('just `unbalanced')), {})

local items = replay._extract_all('https://k.test/a `run me`')
for _, it in ipairs(items) do
  for k in pairs(it) do
    assert(
      k == 'id' or k == 'title' or k == 'subtitle' or k == 'icon' or k == 'detail' or k == 'ctxline', -- summarizer input; stripped before pick/cache
      'undocumented key ' .. k
    )
  end
end
print('ok   pick items clean of ranking keys')

-- titles stay short for the fixed-width palette; ids stay typeable
local shown = replay._extract_all('see https://github.com/TopGolf/strapi-cms/pull/new/feat-x done')
assert(#shown == 1, 'url fixture: ' .. #shown)
assert(
  shown[1].id == 'open https://github.com/TopGolf/strapi-cms/pull/new/feat-x',
  'id lost the command: ' .. shown[1].id
)
assert(shown[1].title == 'github.com/TopGolf/strapi-cms/pull/new/feat-x', 'title not displayized: ' .. shown[1].title)
local bt1 = replay._extract_all('run `git push -u origin HEAD`')
assert(bt1[1].title == 'git push -u origin HEAD' and bt1[1].id == bt1[1].title, 'backtick title/id wrong')
print('ok   titles displayized, ids keep full command')

-- middle elision: two long URLs under one repo must show distinct tails,
-- keep full ids, and stay within the palette's ~43-cell row
local twin = replay._extract_all(
  'x https://github.com/TopGolf/strapi-cms/pull/new/feat-TGA-18210-update-booking-content y '
    .. 'z https://github.com/TopGolf/strapi-cms/pull/new/feat-TGA-99999-zz-other-branch w'
)
assert(#twin == 2, 'twin count: ' .. #twin)
local ta, tb = twin[1].title, twin[2].title
assert(ta ~= tb, 'twins collapsed to one title: ' .. ta)
assert(#ta <= 45 and #tb <= 45, 'title over palette row: ' .. #ta .. '/' .. #tb)
local both = ta .. '|' .. tb
assert(both:find('…', 1, true), 'no ellipsis: ' .. both)
assert(both:find('booking-content', 1, true) and both:find('other-branch', 1, true), 'tails lost: ' .. both)
assert(both:find('github.com/TopGolf/strap', 1, true), 'heads lost: ' .. both)
local twin_ids = {}
for _, it in ipairs(twin) do
  twin_ids[it.id] = true
end
assert(
  twin_ids['open https://github.com/TopGolf/strapi-cms/pull/new/feat-TGA-18210-update-booking-content'],
  'id elided'
)
assert(twin_ids['open https://github.com/TopGolf/strapi-cms/pull/new/feat-TGA-99999-zz-other-branch'], 'id elided')
print('ok   long twins: distinct tail-visible titles, full ids')

-- setup{title_width=N} overrides the elision budget (client-width A/B knob)
local Mtw = load_plugin()
Mtw.setup { skip_keybinds = true, title_width = 10 }
local tw = Mtw._extract_all(
  'x https://github.com/TopGolf/strapi-cms/pull/new/feat-TGA-18210-update-booking-content y '
    .. 'z https://acme.test/short-ccc w'
)
assert(#tw == 2, 'tw count: ' .. #tw)
-- newest first: [1] = acme.test (19 chars, elided at width 10), [2] = github twin
assert(
  tw[1].title:find('acm', 1, true) and tw[1].title:find('…', 1, true) and #tw[1].title <= 10,
  'width 10 not applied: ' .. tw[1].title
)
assert(tw[2].title:find('git', 1, true) and tw[2].title:find('tent', 1, true), 'twin not head+tail: ' .. tw[2].title)
local Mwide = load_plugin()
Mwide.setup { skip_keybinds = true, title_width = 200 }
local wide = Mwide._extract_all('see https://github.com/TopGolf/strapi-cms/pull/new/feat-x done')
assert(wide[1].title == 'github.com/TopGolf/strapi-cms/pull/new/feat-x', 'wide title elided: ' .. wide[1].title)
print('ok   title_width overrides elision budget')

-- elide_middle never splits a multibyte char at either cut
local util_mod = require('rex_replay.util')
local mb = string.rep('a', 24) .. '\228\128\128\228\128\129' .. string.rep('b', 30) -- 3-byte chars across the head cut
local el = util_mod.elide_middle(mb)
local function valid_utf8(s)
  local i, n = 1, #s
  while i <= n do
    local b = s:byte(i)
    local len = b < 0x80 and 1
      or (b >= 0xF0 and 4 or (b >= 0xE0 and 3 or (b >= 0xC0 and 2 or error('stray continuation'))))
    assert(b < 0x80 or b >= 0xC0, 'lead byte expected at ' .. i)
    i = i + len
  end
  return true
end
assert(valid_utf8(el), 'elision produced invalid UTF-8')
assert(el:find('…', 1, true), 'no ellipsis')
print('ok   middle elision is utf-8 safe')

-- custom extractors: pattern + prefix/postfix; function extractor
local M2 = load_plugin()
M2.setup {
  skip_keybinds = true,
  extractors = {
    { label = 'tickets', prefix = 'jira view', pattern = 'ABC%-%d+' },
    {
      label = 'nums',
      postfix = '--json',
      extractor = function(s)
        local out = {}
        for m in string.gmatch(s, '%d%d%d%d+') do
          out[#out + 1] = m
        end
        return out
      end,
    },
  },
}
check(
  'custom pattern + function extractors',
  ids(M2._extract_all('ABC-123 then ABC-456 on port 8080')),
  { 'jira view ABC-456', 'jira view ABC-123', '8080 --json' }
)

assert(
  not pcall(
    M2.setup,
    { skip_keybinds = true, extractors = { { label = 'b', pattern = 'x', extractor = function() end } } }
  ),
  'both must error'
)
assert(not pcall(M2.setup, { skip_keybinds = true, extractors = { { label = 'b' } } }), 'neither must error')
print('ok   validation errors')

-- ── selection flow ────────────────────────────────────────────────────────
logged = {}
local M3 = load_plugin()
M3.setup { replay_key = 'l', recall_key = 'q' }
local bind_l, bind_q
for _, l in ipairs(logged) do
  if l == 'bind ctrl+b>l replay_command' then
    bind_l = true
  end
  if l == 'bind ctrl+b>q replay_recall' then
    bind_q = true
  end
end
assert(bind_l and bind_q, 'actions not bound: ' .. table.concat(logged, ', '))
print('ok   ctrl+b>l/q bind the actions')

local ctx = { block_id = 'block:test' }
local function reset()
  written, picks_shown = {}, {}
end

fake_output = 'https://a.test/h\n`make deploy`\nhttps://b.test/x'
rex.ui.pick = function(opts)
  picks_shown[#picks_shown + 1] = opts
  return opts.items[2].id
end
actions.replay_command.run(ctx)
assert(
  #picks_shown == 1 and #picks_shown[1].items == 3,
  'picker: ' .. #picks_shown .. '/' .. #(picks_shown[1] and picks_shown[1].items or {})
)
assert(written[1] == picks_shown[1].items[2].id, 'wrong item typed')
print('ok   multi-match pick types chosen')

reset()
rex.ui.pick = function(opts)
  picks_shown[#picks_shown + 1] = opts
  return opts.items[1].id
end
actions.replay_recall.run(ctx)
assert(#picks_shown == 1 and #picks_shown[1].items == 3 and written[1] == picks_shown[1].items[1].id, 'recall broke')
print('ok   recall serves cached list')

reset()
rex.ui.pick = function()
  return nil, 'cancelled'
end
actions.replay_command.run(ctx)
assert(#written == 0, 'typed after cancel')
print('ok   cancel types nothing')

reset()
fake_output = 'solo https://solo.test/one'
actions.replay_command.run(ctx)
assert(#picks_shown == 0 and written[1] == 'open https://solo.test/one', 'single path broke')
print('ok   single match types directly')

reset()
fake_output = 'nothing at all'
actions.replay_command.run(ctx)
assert(#picks_shown == 0 and #written == 0, 'empty did something')
print('ok   empty output no-op')

reset()
fake_output = 'CAPTURE_FAIL'
actions.replay_command.run(ctx)
assert(#picks_shown == 0 and #written == 0, 'capture failure leaked')
fake_output = ''
print('ok   capture failure handled')

-- corrupt cache logs distinctly
local f = io.open(replay._cache_path(), 'w')
f:write('}{ not json')
f:close()
logged = {}
actions.replay_recall.run(ctx)
local corrupt_logged = false
for _, l in ipairs(logged) do
  if l:find('corrupt', 1, true) then
    corrupt_logged = true
  end
end
assert(corrupt_logged, 'corrupt cache not logged')
print('ok   corrupt cache logged distinctly')

-- ── capture paging (blob server) ─────────────────────────────────────────
local parts = {}
for i = 1, 3000 do
  parts[i] = string.rep('x', 400) .. '-https://stale.test/' .. i .. '\n'
end
parts[#parts + 1] = 'TAIL https://fresh.test/end\n'
local big = table.concat(parts)

blob, blob_page, read_calls, fail_after = big, 983040, 0, nil
local t, e = replay._capture_text('b')
assert(t and t:find('fresh.test/end') and t:find('stale.test/3000') and #t <= 131072, 'paged tail: ' .. tostring(e))
print('ok   paged tail has newest (' .. read_calls .. ' reads)')

blob_page = 65536
read_calls = 0
t, e = replay._capture_text('b')
assert(t and t:find('fresh.test/end') and read_calls >= 3, 'small pages: ' .. tostring(e))
print('ok   multi-page paging')

fail_after = 1
t, e = replay._capture_text('b')
assert(t == nil and e ~= nil, 'stalled paging must fail')
fail_after = nil
print('ok   blob errors surface as failure')

-- UTF-8: the last-n cut must advance off a continuation byte.
-- bytes: 1=X, 2-4=E4 B8 96, 5..=a's -> the last-n start lands on byte 4
-- (a continuation byte), which tail_bytes must skip forward past.
local s = 'X' .. '\228\184\150' .. string.rep('a', 131071)
assert(s:byte(#s - 131072 + 1) == 150, 'fixture: boundary should be a continuation byte')
local tb = replay._tail_bytes(s, 131072)
assert(tb == string.rep('a', 131071), 'tail_bytes left a split char, first byte ' .. tb:byte(1))
assert(replay._tail_bytes(s, #s) == s, 'short string untouched')
print('ok   tail cut utf-8 safe')

-- ── fm summarizer ─────────────────────────────────────────────────────────
blob = nil -- the paging tests leave the blob server armed; capture must use fake_output
-- fake `fm` is scripted via fm_reset(stdout, mode); fm.calls records every
-- argv. The probe call (fm --help) is excluded from respond counts.
local function respond_calls()
  local n = 0
  for _, argv in ipairs(fm.calls) do
    if argv[2] ~= '--help' then
      n = n + 1
    end
  end
  return n
end
local function last_prompt()
  local argv = fm.calls[#fm.calls]
  return argv and argv[#argv]
end

local sum = require('rex_replay.summarizer')

-- parsing
local p = sum._parse_labels('1: open pull request\n2: install package\n', 2)
assert(p[1] == 'open pull request' and p[2] == 'install package', 'numbered parse')
local p2 = sum._parse_labels('open pull request\ninstall package\n', 2)
assert(p2[1] == 'open pull request' and p2[2] == 'install package', 'positional fallback')
local p3 = sum._parse_labels('Sure! Here you go:\n1: open pull request\n2: install package\n', 2)
assert(p3[1] == 'open pull request' and p3[2] == 'install package', 'preamble not skipped: ' .. tostring(p3[1]))
-- positional zip must refuse anything but exactly one line per item: a
-- shifted label misdescribes the command that gets typed
assert(next(sum._parse_labels('open PR\ninstall pkg\n', 2)) ~= nil, 'exact positional rejected')
local p5 = sum._parse_labels('Sure! Here you go:\nopen PR\ninstall pkg\n', 2)
assert(next(p5) == nil, 'shifted positional accepted: ' .. tostring(p5[1]))
local p6 = sum._parse_labels('Sure!\nopen PR\n', 2)
assert(next(p6) == nil, 'preamble-sized positional accepted: ' .. tostring(p6[1]))
local p7 = sum._parse_labels('open PR\n', 2)
assert(next(p7) == nil, 'short positional accepted')
local q = sum._clean_label(' "Open the PR. " ')
assert(q == 'Open the PR', 'quote/period cleanup: ' .. tostring(q))
assert(sum._clean_label("I can't summarize that.") == nil, 'refusal not rejected')
assert(sum._clean_label('   ') == nil, 'blank not rejected')
local long = sum._clean_label(string.rep('z', 200))
assert(#long <= 43, 'label over width: ' .. #long)
assert(long:find('…', 1, true), 'over-long label not elided')
print('ok   fm label parsing, cleanup, width clamp')

-- prompt carries the length limit and the numbered commands
fm_reset('1: a\n2: b\n')
local mi = {
  { id = 'open https://one.test/x', title = 'one' },
  { id = 'open https://two.test/y', title = 'two' },
}
sum.configure {}
sum.summarize(mi)
local pr = last_prompt()
assert(
  pr:find('1: open https://one.test/x', 1, true) and pr:find('2: open https://two.test/y', 1, true),
  'prompt items'
)
local argv = fm.calls[#fm.calls]
local function argv_at(flag)
  for i, a in ipairs(argv) do
    if a == flag then
      return argv[i + 1], i
    end
  end
end
assert(argv_at('-i'):find('shorter than 43 characters', 1, true), 'prompt lacks length limit')
assert(argv_at('--model') == 'system', 'on-device model not pinned')
local saw_no_stream = false
for _, a in ipairs(argv) do
  if a == '--no-stream' then
    saw_no_stream = true
  end
end
assert(saw_no_stream, 'streaming not disabled')
local huge = { { id = string.rep('u', 500), title = 'u' }, { id = 'v', title = 'v' } }
sum.summarize(huge)
assert(
  last_prompt():find(string.rep('u', 200), 1, true) and not last_prompt():find(string.rep('u', 201), 1, true),
  'id trim'
)
-- only the first max_items items reach the prompt
local many = {}
for i = 1, 30 do
  many[i] = { id = 'cmd number ' .. i, title = 'raw' .. i }
end
sum.configure { max_items = 5 }
sum.summarize(many)
local pr2 = last_prompt()
assert(pr2:find('5: cmd number 5', 1, true) and not pr2:find('6: cmd number 6', 1, true), 'prompt not sliced')
sum.configure {}
print('ok   prompt: length limit, model pinned, --no-stream, id trim, max_items slice')

-- terminal context: items carry the line they were found on, it reaches
-- the model, and the public summarize strips it (pick/cache never see it)
local citems = replay._extract_all(
  "remote: Create a pull request for 'feat-x' at https://acme.test/pull/new/feat-x done\n"
    .. 'then visit https://docs.test/guide ok'
)
assert(#citems == 2, 'ctx fixture: ' .. #citems)
local acme
for _, it in ipairs(citems) do
  if it.id:find('acme', 1, true) then
    acme = it
  end
end
assert(acme, 'no acme item')
assert(
  acme.ctxline and acme.ctxline:find("Create a pull request for 'feat-x'", 1, true),
  'ctxline missing: ' .. tostring(acme.ctxline)
)
assert(not acme.ctxline:find('\n'), 'ctxline spans lines')
local cprompt = sum._build_prompt(citems, 2)
assert(
  cprompt:find('(seen in terminal output: remote: Create a pull request', 1, true),
  'ctxline not in prompt: ' .. cprompt:sub(1, 120)
)
fm_reset('1: c\n2: d\n')
sum.configure {}
sum.summarize(citems)
for _, it in ipairs(citems) do
  assert(it.ctxline == nil, 'ctxline leaked past summarize')
end
print('ok   fm prompt carries terminal line context; ctxline stripped after')

-- exec timeout budget: opts.timeout is a hard CAP on the fm wait (the
-- picker must not hide behind a cosmetic feature); the 4 + 0.5/label
-- scaling can only shorten it, never exceed the cap
local mi2 = { { id = 'open https://a.test/x', title = 'x' }, { id = 'open https://b.test/y', title = 'y' } }
sum.configure {}
sum.summarize(mi2)
assert(fm.last_opts.timeout == 5, 'small batch budget: ' .. tostring(fm.last_opts.timeout))
sum.configure { timeout = 45 }
sum.summarize(mi2)
assert(fm.last_opts.timeout == 5, 'small batch should scale below cap: ' .. tostring(fm.last_opts.timeout))
local many2 = {}
for i = 1, 40 do
  many2[i] = { id = 'cmd ' .. i, title = 'r' }
end
sum.summarize(many2) -- count 24 -> 4 + 12 = 16, under the 45 cap
assert(fm.last_opts.timeout == 16, 'big batch budget: ' .. tostring(fm.last_opts.timeout))
sum.configure {}
sum.summarize(many2) -- scaling 16 capped by default timeout 10
assert(fm.last_opts.timeout == 10, 'cap not applied: ' .. tostring(fm.last_opts.timeout))
print('ok   exec timeout: scaling under a hard cap, picker never delayed past timeout')

-- titles replaced, ids untouched, summaries cached for recall
logged = {}
local M4 = load_plugin()
M4.setup { skip_keybinds = true }
fm_reset('1: read the guide\n2: run make deploy\n3: open PR feat-login in web\n')
fake_output = 'https://git.test/pr/new/feat-login `make deploy` https://docs.test/guide'
written, picks_shown = {}, {}
rex.ui.pick = function(o)
  picks_shown[#picks_shown + 1] = o
  return o.items[1].id
end
actions.replay_command.run { block_id = 'block:test' }
local shown_items = picks_shown[1].items
-- rex.ui.pick errors on undocumented keys; ctxline must be gone by now
for _, it in ipairs(shown_items) do
  for k in pairs(it) do
    assert(
      k == 'id' or k == 'title' or k == 'subtitle' or k == 'icon' or k == 'detail',
      'pick item undocumented key ' .. k
    )
  end
end
assert(shown_items[1].title == 'read the guide', 'title 1: ' .. shown_items[1].title)
assert(shown_items[2].title == 'run make deploy', 'title 2: ' .. shown_items[2].title)
assert(shown_items[3].title == 'open PR feat-login in web', 'title 3: ' .. shown_items[3].title)
-- labeled rows show the raw command underneath, in the quieter subtitle
assert(shown_items[1].subtitle == 'docs.test/guide', 'subtitle 1: ' .. tostring(shown_items[1].subtitle))
assert(shown_items[3].subtitle == 'git.test/pr/new/feat-login', 'subtitle 3: ' .. tostring(shown_items[3].subtitle))
assert(shown_items[1].detail == 'URIs' and shown_items[2].detail == 'backticks', 'detail label lost')
assert(shown_items[3].id == 'open https://git.test/pr/new/feat-login', 'id changed!: ' .. shown_items[3].id)
assert(written[1] == 'open https://docs.test/guide', 'typed not full id: ' .. tostring(written[1]))
reset()
rex.ui.pick = function(o)
  picks_shown[#picks_shown + 1] = o
  return o.items[1].id
end
actions.replay_recall.run { block_id = 'block:test' }
local rec = picks_shown[1].items
assert(
  #rec == 3 and rec[1].title == 'read the guide' and rec[3].title == 'open PR feat-login in web',
  'recall lost summaries'
)
assert(rec[3].id == 'open https://git.test/pr/new/feat-login', 'recall lost id')
print('ok   fm titles shown + cached, ids stay full commands')

-- duplicated labels fall back to raw elided titles (duplicates defeat the list)
local M5 = load_plugin()
M5.setup { skip_keybinds = true }
fm_reset('1: open GitHub link\n2: open GitHub link\n3: read the guide\n')
written, picks_shown = {}, {}
rex.ui.pick = function(o)
  picks_shown[#picks_shown + 1] = o
  return nil, 'cancelled'
end
actions.replay_command.run { block_id = 'block:test' }
local dup = picks_shown[1].items
assert(dup[1].title == 'docs.test/guide', 'dup label applied: ' .. dup[1].title)
assert(dup[2].title == 'make deploy', 'dup label applied: ' .. dup[2].title)
assert(dup[3].title == 'read the guide', 'unique label lost: ' .. dup[3].title)
-- unlabeled rows must NOT get subtitle=raw (would print the string twice)
assert(dup[1].subtitle == nil, 'fallback row has subtitle: ' .. tostring(dup[1].subtitle))
assert(dup[2].subtitle == nil, 'fallback row has subtitle: ' .. tostring(dup[2].subtitle))
assert(dup[3].subtitle == 'git.test/pr/new/feat-login', 'labeled row lacks raw subtitle: ' .. tostring(dup[3].subtitle))
print('ok   duplicate fm labels fall back to raw titles')

-- missing items keep their raw title (partial answers are fine)
local M6 = load_plugin()
M6.setup { skip_keybinds = true }
fm_reset('1: only the first\n')
written, picks_shown = {}, {}
rex.ui.pick = function(o)
  picks_shown[#picks_shown + 1] = o
  return nil, 'cancelled'
end
actions.replay_command.run { block_id = 'block:test' }
local part = picks_shown[1].items
assert(part[1].title == 'only the first', 'partial 1: ' .. part[1].title)
assert(part[3].title == 'git.test/pr/new/feat-login', 'partial 3 raw: ' .. part[3].title)
print('ok   missing fm labels keep raw titles')

-- failure modes fall back without blocking; timeouts never trip the breaker
local M7 = load_plugin()
M7.setup { skip_keybinds = true }
local sum7 = require('rex_replay.summarizer')
fm_reset('', 'timeout')
written, picks_shown = {}, {}
rex.ui.pick = function(o)
  picks_shown[#picks_shown + 1] = o
  return nil, 'cancelled'
end
for _ = 1, 5 do
  actions.replay_command.run { block_id = 'block:test' }
end
local tout = picks_shown[5].items
assert(tout[1].title ~= 'open PR', 'timeout applied a label')
assert(tout[1].title == 'docs.test/guide', 'timeout lost raw title: ' .. tout[1].title)
assert(respond_calls() == 5, 'timeout tripped breaker: ' .. respond_calls() .. ' calls')
local logged_timeout = false
for _, l in ipairs(logged) do
  if l:find('timeout', 1, true) then
    logged_timeout = true
  end
end
assert(logged_timeout, 'timeout not logged')

fm_reset('', 'fail')
local respond_n_before = respond_calls()
for _ = 1, 4 do
  actions.replay_command.run { block_id = 'block:test' }
end
assert(respond_calls() - respond_n_before == 3, 'hard-fail breaker: ' .. (respond_calls() - respond_n_before))
local sum7o = require('rex_replay.summarizer')._opts
assert(
  sum7o._available == false and sum7o._fails >= 3,
  'breaker state: ' .. tostring(sum7o._available) .. '/' .. tostring(sum7o._fails)
)

-- the breaker counts CONSECUTIVE failures: fails, a good batch, fails
-- again (fewer than 3 in a row) must still be calling fm
local M7b = load_plugin()
M7b.setup { skip_keybinds = true }
rex.ui.pick = function(o)
  picks_shown[#picks_shown + 1] = o
  return nil, 'cancelled'
end
local function replay_n(n)
  for _ = 1, n do
    actions.replay_command.run { block_id = 'block:test' }
  end
end
local sum7b = require('rex_replay.summarizer')._opts
local n0 = fm.responds_total
fm_reset('', 'fail')
replay_n(2)
fm_reset('1: read the guide\n2: run make deploy\n3: open PR feat-login in web\n')
replay_n(1)
fm_reset('', 'fail')
replay_n(2)
assert(fm.responds_total - n0 == 5, 'consecutive-fail breaker tripped early: ' .. (fm.responds_total - n0))
assert(sum7b._available ~= false, 'breaker stayed tripped through success')
replay_n(1) -- third in a row now trips
assert(
  fm.responds_total - n0 == 6 and sum7b._available == false,
  'breaker never tripped: ' .. (fm.responds_total - n0) .. '/' .. tostring(sum7b._available)
)
print('ok   breaker counts consecutive failures only')
print('ok   fm timeouts never disable; 3 hard failures trip breaker')

-- fm absent: probe fails, respond is never attempted
local M8 = load_plugin()
M8.setup { skip_keybinds = true }
fm_reset('', 'absent')
written, picks_shown = {}, {}
rex.ui.pick = function(o)
  picks_shown[#picks_shown + 1] = o
  return nil, 'cancelled'
end
actions.replay_command.run { block_id = 'block:test' }
assert(respond_calls() == 0, 'responded without fm')
assert(picks_shown[1].items[1].title == 'docs.test/guide', 'absent fm lost raw title')
print('ok   fm absent uses raw titles, never responds')

-- disable switch + single item short-circuit
local M9 = load_plugin()
M9.setup { skip_keybinds = true, summarize = { enabled = false } }
fm_reset('1: nope\n2: nope2\n3: nope3\n')
written, picks_shown = {}, {}
rex.ui.pick = function(o)
  picks_shown[#picks_shown + 1] = o
  return nil, 'cancelled'
end
actions.replay_command.run { block_id = 'block:test' }
assert(respond_calls() == 0, 'summarize ran while disabled')
assert(picks_shown[1].items[1].title == 'docs.test/guide', 'disabled path lost raw title')
fm_reset('1: solo\n')
written, picks_shown = {}, {}
fake_output = 'solo https://solo.test/one'
actions.replay_command.run { block_id = 'block:test' }
assert(respond_calls() == 0, 'fm called for single item')
assert(written[1] == 'open https://solo.test/one', 'single path broke under summarizer')
fake_output = 'https://git.test/pr/new/feat-login `make deploy` https://docs.test/guide'
print('ok   summarize disabled + single item never call fm')

-- ── isolation guard (must stay last) ─────────────────────────────────────
-- No fixture item may ever reach the real recall cache: if the override
-- regressed, restore the snapshot and fail so a stale list can't be typed
-- into the next real replay_recall.
local after = slurp(real_cache_path)
if after ~= cache_snapshot then
  local out = io.open(real_cache_path, 'w')
  if out then
    if cache_snapshot then
      out:write(cache_snapshot)
    end
    out:close()
  end
  if cache_snapshot == nil then
    os.remove(real_cache_path)
  end
  print('FAIL real recall cache was touched: ' .. real_cache_path)
  os.exit(1)
end
print('ok   real recall cache untouched')

print('ALL PASS')
