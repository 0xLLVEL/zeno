local before = #workspace:GetChildren()
local part = Instance.new("Part")
part.Name = "ZenoProbe"
part.Parent = workspace
local after = #workspace:GetChildren()
local found = workspace:FindFirstChild("ZenoProbe")
return tostring(before) .. "|" .. tostring(after) .. "|" .. tostring(found and found.ClassName)
