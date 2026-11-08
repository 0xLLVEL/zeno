local ok, err = pcall(function() workspace.Gravity = 0 end)
return ok, err, workspace.Gravity
