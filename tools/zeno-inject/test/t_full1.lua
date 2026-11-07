local t = {a=1, b=2}
t.c = 3
local s = "ab" .. "cd"
local n = #s
local f = function(x) return x*2 end
return f(n) + t.a + t.b + t.c
