local before = #workspace:GetChildren()
local part = Instance.new("Part")
part.Name = "ZenoProbe"
part.Parent = workspace
local after = #workspace:GetChildren()
local cls = part.ClassName
return tostring(before) .. "|" .. tostring(after) .. "|" .. cls
