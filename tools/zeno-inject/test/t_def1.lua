ZENO_PROBE = "pending"
local d = task and (task.defer or task.spawn)
if not d then
    ZENO_PROBE = "no-task"
    return ZENO_PROBE
end
d(function()
    local ok, res = pcall(Instance.new, "Part")
    ZENO_PROBE = tostring(ok) .. "|" .. tostring(res)
end)
return ZENO_PROBE
