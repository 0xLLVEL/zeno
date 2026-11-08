local d = task and (task.defer or task.spawn)
return type(d)
