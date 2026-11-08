local ok, place = pcall(function()
    return game.PlaceId
end)
local before = #workspace:GetChildren()
local part = Instance.new("Part")
part.Name = "ZenoBig"
part.Anchored = true
part.Parent = workspace
local after = #workspace:GetChildren()
local name = part.Name
local cls = part.ClassName
return tostring(before) .. "|" .. tostring(after) .. "|" .. name .. "|" .. cls .. "|" .. tostring(ok) .. "|" .. tostring(place)