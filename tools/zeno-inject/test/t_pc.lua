local ok, r = pcall(function()
  local p = Instance.new("Part")
  p.Name = "zeno_probe"
  return p.Name .. "|" .. p.ClassName
end)
return tostring(ok) .. "|" .. tostring(r)
