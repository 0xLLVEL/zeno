local out = "unset"
task.spawn(function()
    local ok, res = pcall(Instance.new, "Part")
    out = tostring(ok) .. "|" .. tostring(res)
end)
return out
