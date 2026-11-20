-- Capture: the newest terminal output as plain text, using only Rex block
-- methods.

local util = require('rex_replay.util')

local TERMINAL = 'com.superlogical.terminal'
local CAPTURE_BYTES = 131072 -- how much of the newest output to scan
local TAIL_CHUNK = 983040 -- blob_read's per-call cap
local MAX_PAGES = 128 -- stall guard; 128 × 960 KiB exceeds any scrollback

-- Try the whole screen + scrollback in one reply first (no max_bytes: the
-- server answers fully or fails with too_large). When it fails, page the
-- result with blob_read and keep only the trailing window — replay wants
-- the freshest output, so dropping old head is fine.
--
-- The tail position must come from blob_read's OWN total: format's total is
-- measured after JSON encoding, while blob_read's offsets are plain bytes,
-- and mixing them seeks into the middle of the output (measured against a
-- 170 KiB scrollback: a seek seeded from format.total landed short and came
-- back eof=false, missing the newest lines). So: probe at offset 0 to learn
-- blob_read's total, aim once at total - want, then page forward
-- (offset += #data) until the reply's own eof=true. A page that stalls or
-- errors before eof is a capture FAILURE, not a complete window — extracting
-- from a silently truncated tail would paste stale matches.
local function capture_text(block_id)
  local whole, err = rex.block.call(TERMINAL, 'format', {
    block_id = block_id,
    format = 'text',
    trim = true,
    unwrap = true,
  })
  if whole ~= nil then
    return whole.content or ''
  end
  if err == nil or not tostring(err):find('too_large', 1, true) then
    return nil, err
  end

  local head, herr = rex.block.call(TERMINAL, 'format', {
    block_id = block_id,
    format = 'text',
    trim = true,
    unwrap = true,
    max_bytes = CAPTURE_BYTES,
  })
  if head == nil or head.id == nil then
    return nil, herr or err
  end
  local id = head.id

  local function read(offset)
    return rex.block.call(TERMINAL, 'blob_read', {
      block_id = block_id,
      id = id,
      offset = offset,
      max_bytes = TAIL_CHUNK,
    })
  end

  local probe, perr = read(0)
  if probe == nil then
    return nil, perr
  end

  local window, window_len = {}, 0
  local function keep(data)
    if data == '' then
      return
    end
    window[#window + 1] = data
    window_len = window_len + #data
    while window_len > CAPTURE_BYTES * 2 and #window > 1 do
      window_len = window_len - #window[1]
      table.remove(window, 1)
    end
  end
  keep(probe.data or '')
  if probe.eof then
    return util.tail_bytes(table.concat(window), CAPTURE_BYTES)
  end

  -- aim once near the end using blob_read's own units, then page to eof
  local offset = #probe.data
  if type(probe.total) == 'number' and probe.total > offset + CAPTURE_BYTES then
    local seek = probe.total - CAPTURE_BYTES
    local jumped, jerr = read(seek)
    if jumped ~= nil and jumped.data ~= nil and jumped.data ~= '' then
      -- offset is in the same units the reply counted (#data advanced it),
      -- so trusting the seek cannot lose the tail: paging continues from here
      window, window_len = {}, 0
      keep(jumped.data)
      if jumped.eof then
        return util.tail_bytes(table.concat(window), CAPTURE_BYTES)
      end
      offset = seek + #jumped.data
    else
      -- seek overshot the end; fall through and page from the probe
      rex.log('debug', '[replay] tail seek failed (' .. tostring(jerr) .. '); paging from probe')
    end
  end

  for _ = 1, MAX_PAGES do
    local chunk, cerr = read(offset)
    if chunk == nil then
      return nil, cerr
    end
    local data = chunk.data or ''
    if data == '' then
      if chunk.eof then
        return util.tail_bytes(table.concat(window), CAPTURE_BYTES)
      end
      return nil, 'blob_read stalled at offset ' .. offset
    end
    keep(data)
    offset = offset + #data
    if chunk.eof then
      return util.tail_bytes(table.concat(window), CAPTURE_BYTES)
    end
  end
  return nil, 'blob_read did not reach eof within ' .. MAX_PAGES .. ' pages'
end

return {
  capture_text = capture_text,
  CAPTURE_BYTES = CAPTURE_BYTES,
}
