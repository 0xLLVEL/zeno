local s = "ab"
local t = {1,2,3,4}
local acc = 0
for _, v in ipairs(t) do acc = acc + v end
local m = s .. tostring(#t)
local q = s:upper()
local up = 5
local function add(x) return x + up end
return add(#m) + acc
