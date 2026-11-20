-- Shared helpers: logging, the tail-safe byte cut, and the recall cache.

local function log_msg(msg)
  return '[replay] ' .. msg
end

local function log_info(msg)
  rex.log('info', log_msg(msg))
end

local function log_warn(msg)
  rex.log('warn', log_msg(msg))
end

local function log_error(msg)
  rex.log('error', log_msg(msg))
end

local function trim(s)
  return (s:gsub('^%s+', ''):gsub('%s+$', ''))
end

-- Collapse embedded newlines to spaces: an item typed at the prompt must
-- never carry a newline that would execute it.
local function strip_returns(s)
  return (s:gsub('[\r\n]', ' '))
end

-- Keep the last n bytes without cutting through a UTF-8 sequence: a cut can
-- otherwise land on a continuation byte and paste mojibake at the prompt.
local function tail_bytes(s, n)
  if #s <= n then
    return s
  end
  local start = #s - n + 1
  while start < #s do
    local b = s:byte(start)
    if b < 0x80 or b >= 0xC0 then
      break -- ASCII or a lead byte: a safe place to cut
    end
    start = start + 1 -- continuation byte; move to the character boundary
  end
  return s:sub(start)
end

-- End-truncation (what the palette does to long titles) always discards the
-- distinguishing suffix, so long picker titles are elided in the MIDDLE
-- instead: the head (scheme/domain/path start) and the tail (branch, PR
-- number, query) both survive, which is where matches actually differ.
-- Byte cuts walk to UTF-8 boundaries in both directions.
local ELLIPSIS = '\226\128\166' -- U+2026
local TITLE_HEAD = 24
local TITLE_TAIL = 18

local function elide_middle(s, width)
  local head_n, tail_n = TITLE_HEAD, TITLE_TAIL
  if width ~= nil then
    local budget = math.max(4, width - #ELLIPSIS)
    head_n = math.floor(budget / 2)
    tail_n = budget - head_n
    if head_n < 1 then
      head_n = 1
    end
    if tail_n < 1 then
      tail_n = 1
    end
  end
  if #s <= head_n + #ELLIPSIS + tail_n then
    return s
  end
  -- head: end at a character boundary (back up off a continuation byte)
  local head_end = head_n
  while head_end > 1 do
    local b = s:byte(head_end + 1)
    if b == nil or b < 0x80 or b >= 0xC0 then
      break -- next byte starts a character; head ends clean
    end
    head_end = head_end - 1
  end
  local tail = tail_bytes(s, tail_n)
  return s:sub(1, head_end) .. ELLIPSIS .. tail
end

-- ─── Recall cache ─────────────────────────────────────────────────────────

local cache_dir_override -- test hook; nil reads the environment

local function cache_path()
  if cache_dir_override then
    return cache_dir_override .. '/cache.json'
  end
  local dir = os.getenv('XDG_CACHE_HOME')
  if dir == nil or dir == '' then
    dir = (os.getenv('HOME') or '.') .. '/.cache'
  end
  return dir .. '/rex-replay/cache.json'
end

local function cache_results(items)
  local path = cache_path()
  local encoded = rex.json.encode(items)
  if encoded == nil then
    return
  end
  local f = io.open(path, 'w')
  if f == nil then
    rex.exec { 'mkdir', '-p', path:match('^(.*)/[^/]*$') }
    f = io.open(path, 'w')
    if f == nil then
      log_warn('cannot write cache: ' .. path)
      return
    end
  end
  f:write(encoded)
  f:close()
end

local function load_cache()
  local f = io.open(cache_path(), 'r')
  if f == nil then
    return {} -- never extracted; distinct from corrupt below
  end
  local raw = f:read('*a')
  f:close()
  local items = rex.json.decode(raw or '')
  if type(items) ~= 'table' then
    log_warn('cache is corrupt: ' .. cache_path())
    return {}
  end
  return items
end

return {
  log_info = log_info,
  log_warn = log_warn,
  log_error = log_error,
  trim = trim,
  strip_returns = strip_returns,
  tail_bytes = tail_bytes,
  cache_path = cache_path,
  cache_results = cache_results,
  load_cache = load_cache,
  elide_middle = elide_middle,
  -- internal, for the test harness
  _set_cache_dir = function(dir)
    cache_dir_override = dir
  end,
}
