local ok, res = pcall(function()
    local p = Instance.new("Part")
    p.Name = "zeno_probe"
    p.Parent = workspace
    return p.ClassName
end)
return ok, res
