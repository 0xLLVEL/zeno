local before = #workspace:GetChildren()
local p = Instance.new("Part")
p.Name = "zeno_probe"
p.Parent = workspace
local after = #workspace:GetChildren()
return before, after, p.ClassName
