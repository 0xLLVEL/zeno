local ok, p = pcall(Instance.new, "Part")
return ok, p, type(pcall), type(Instance)
