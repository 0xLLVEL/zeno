local f = ...
local co = coroutine.create(f)
local ok, res = coroutine.resume(co)
return tostring(ok) .. "|" .. tostring(res)
