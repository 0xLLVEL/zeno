local before = #workspace:GetChildren()
local part = Instance.new("Part")
part.Name = "ZenoProbe"
part.Anchored = true
part.Parent = workspace
local after = #workspace:GetChildren()
return tostring(before) .. "|" .. tostring(after)
