-- Extraction: turn captured text into pick-ready items, freshest first.

local util = require('rex_replay.util')

local MAX_ITEMS = 250 -- rex.ui.pick takes at most 2,000; 250 is plenty

-- An extractor: { label = string, icon = string?, prefix = string?,
--                 postfix = string?, pattern = string } or
--                { ..., patterns = string[], clean = fun(string): string } or
--                { ..., extractor = fun(s: string): string[] }

-- Characters a URL cannot really end with in command output.
local url_trailing = {}
for _, c in ipairs { '.', ',', ';', ':', '!', '?', ')', ']', '}', '"', "'", '`' } do
  url_trailing[c:byte()] = true
end

local function trim_url(s)
  local finish = #s
  while finish > 0 and url_trailing[s:byte(finish)] do
    finish = finish - 1
  end
  return s:sub(1, finish)
end

local default_extractors = {
  -- commands inside `backticks`, one per line
  {
    label = 'backticks',
    icon = 'code',
    pattern = '`([^`\r\n]+)`',
  },
  -- URLs, bracketed forms first so the brackets don't ride along
  {
    label = 'URIs',
    icon = 'link',
    prefix = 'open',
    clean = trim_url,
    patterns = {
      '%((%w+://%S+)%)',
      '%[(%w+://%S+)%]',
      '%{(%w+://%S+)%}',
      '%<(%w+://%S+)%>',
      '%w+://%S+',
    },
  },
}

-- All matches of a Lua pattern in s, with positions, without gmatch so the
-- byte offset survives for the newest-first ordering. Kept whole; the caller
-- trims to the LAST MAX_ITEMS so a flood of matches cannot bury the freshest.
local function find_all(s, pattern)
  local out = {}
  local init = 1
  while true do
    local a, b, cap = s:find(pattern, init)
    if a == nil then
      break
    end
    out[#out + 1] = { text = cap or s:sub(a, b), pos = a }
    init = (b >= a) and (b + 1) or (a + 1)
  end
  return out
end

-- Mirrors the wezterm plugin's validation: exactly one of `extractor` or
-- `pattern` (or, Rex-side only, `patterns`).
local function validate(ex, idx)
  local has_fn = ex.extractor ~= nil
  local has_pat = ex.pattern ~= nil or ex.patterns ~= nil
  local who = ex.label or ('index ' .. idx)
  if has_fn and has_pat then
    error('[replay] cannot define both `extractor` and `pattern`; ' .. who)
  end
  if not has_fn and not has_pat then
    error('[replay] must define at least one of `extractor` or `pattern`; ' .. who)
  end
end

local function normalize(ex)
  if ex.pattern and not ex.patterns then
    ex.patterns = { ex.pattern }
  end
  return ex
end

local active_extractors = {}

local function set_extractors(custom)
  active_extractors = {}
  for _, ex in ipairs(custom or {}) do
    active_extractors[#active_extractors + 1] = normalize(ex)
  end
  for _, ex in ipairs(default_extractors) do
    active_extractors[#active_extractors + 1] = normalize(ex)
  end
  return active_extractors
end

-- Returns pick-ready items: freshest first, deduped on the final label.
local function extract_all(text)
  local items, seen, seq = {}, {}, 0
  for _, ex in ipairs(active_extractors) do
    local found = {}
    if ex.extractor then
      local ok, list = pcall(ex.extractor, text)
      if not ok then
        util.log_warn('extractor ' .. (ex.label or '?') .. ' failed: ' .. tostring(list))
      else
        for _, t in ipairs(type(list) == 'table' and list or {}) do
          if type(t) == 'string' then
            found[#found + 1] = { text = t, pos = -1 } -- custom fns report no position
          end
        end
      end
    else
      for _, pat in ipairs(ex.patterns) do
        for _, m in ipairs(find_all(text, pat)) do
          found[#found + 1] = m
        end
      end
    end
    for _, m in ipairs(found) do
      local t = util.trim(util.strip_returns(m.text))
      if ex.clean then
        t = util.trim(ex.clean(t))
      end
      if t ~= '' then
        local label = (ex.prefix and (ex.prefix .. ' ') or '') .. t .. (ex.postfix and (' ' .. ex.postfix) or '')
        local item = seen[label]
        if item then
          -- keep the single entry but rank by its NEWEST occurrence, so a
          -- URL reprinted minutes later sorts with recent output, not with
          -- the ancient line it first appeared on
          if m.pos > item.pos then
            item.pos = m.pos
            item.seq = seq
            seq = seq + 1
          end
        else
          item = {
            id = label,
            title = label,
            subtitle = ex.label,
            icon = ex.icon,
            pos = m.pos,
            seq = seq,
          }
          seq = seq + 1
          seen[label] = item
          items[#items + 1] = item
        end
      end
    end
  end
  -- newest first; extraction order breaks ties
  table.sort(items, function(a, b)
    if a.pos ~= b.pos then
      return a.pos > b.pos
    end
    return a.seq < b.seq
  end)
  -- keep only the freshest; matches beyond MAX_ITEMS are ancient scrollback
  for i = #items, MAX_ITEMS + 1, -1 do
    items[i] = nil
  end
  -- pick/cache shape: drop the ranking fields so rex.ui.pick and the JSON
  -- cache carry only documented item keys
  for _, item in ipairs(items) do
    item.pos, item.seq = nil, nil
  end
  return items
end

return {
  default_extractors = default_extractors,
  validate = validate,
  set_extractors = set_extractors,
  extract_all = extract_all,
  MAX_ITEMS = MAX_ITEMS,
}
