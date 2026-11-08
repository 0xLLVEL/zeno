local before = #workspace:GetChildren()
local part = Instance.new("Part")
part.Name = "ZenoBig"
part.Anchored = true
part.Parent = workspace
local after = #workspace:GetChildren()
local name = part.Name
local cls = part.ClassName
local place = game.PlaceId
local job = game.JobId
return tostring(before) .. "|" .. tostring(after) .. "|" .. name .. "|" .. cls .. "|" .. tostring(place) .. "|" .. tostring(job)