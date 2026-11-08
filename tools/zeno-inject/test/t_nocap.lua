local kids = workspace:GetChildren()
local name = workspace.Name
local cls = workspace.ClassName
local place = game.PlaceId
local job = game.JobId
local a = #kids
return tostring(a) .. "|" .. name .. "|" .. cls .. "|" .. tostring(place) .. "|" .. tostring(job)
