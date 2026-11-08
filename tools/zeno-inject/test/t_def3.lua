ZENO_PROBE = "pending"
task.defer(function()
    local ok, res = pcall(Instance.new, "Part")
    ZENO_PROBE = tostring(ok) .. "|" .. tostring(res)
end)
return ZENO_PROBE
