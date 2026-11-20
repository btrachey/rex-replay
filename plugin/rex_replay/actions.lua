-- Actions: capture -> extract -> pick -> type, as Rex palette actions.

local util = require('rex_replay.util')
local capture = require('rex_replay.capture')
local extractors = require('rex_replay.extractors')

local TERMINAL = 'com.superlogical.terminal'

local function send_to_pane(block_id, label)
  util.log_info('typing into pane: ' .. label)
  local ok, err = rex.block.call(TERMINAL, 'write', { block_id = block_id, data = label })
  if ok == nil then
    util.log_error('write failed: ' .. tostring(err))
  end
end

-- The wezterm plugin's handle_selection: one match goes straight to the
-- prompt, many go through the picker. Items are cached either way, so
-- replay_recall can offer the same list again.
local function handle_selection(block_id, items)
  if #items == 0 then
    util.log_info('no commands found')
    return
  end
  util.cache_results(items)
  if #items == 1 then
    send_to_pane(block_id, items[1].id)
    return
  end
  local chosen, why = rex.ui.pick {
    title = 'Replay Command',
    placeholder = 'Send command to pane; type to filter',
    items = items,
  }
  if chosen == nil then
    if why ~= 'cancelled' then
      util.log_warn('picker: ' .. tostring(why))
    end
    return
  end
  send_to_pane(block_id, chosen)
end

local function replay_command(ctx)
  local text, err = capture.capture_text(ctx.block_id)
  if text == nil then
    util.log_error('capture failed: ' .. tostring(err))
    return
  end
  handle_selection(ctx.block_id, extractors.extract_all(text))
end

local function replay_recall(ctx)
  handle_selection(ctx.block_id, util.load_cache())
end

local function register_actions()
  rex.action {
    name = 'replay_command',
    title = 'Replay Command From Output',
    category = 'Replay',
    keywords = 'replay extract url backtick paste output',
    run = replay_command,
  }
  rex.action {
    name = 'replay_recall',
    title = 'Recall Extracted Commands',
    category = 'Replay',
    keywords = 'recall replay cached extract paste output',
    run = replay_recall,
  }
end

return {
  register_actions = register_actions,
  replay_command = replay_command,
  replay_recall = replay_recall,
  handle_selection = handle_selection,
}
