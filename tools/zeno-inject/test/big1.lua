local t = {}
local function add(a, b)
    return a + b
end
local function mul(a, b)
    return a * b
end
local function chain(n)
    local acc = 0
    for i = 1, n do
        acc = add(acc, mul(i, 2))
    end
    return acc
end
t.a = chain(10)
t.b = chain(20)
t.c = add(t.a, t.b)
t.d = mul(t.a, t.b)
t.e = tostring(t.c) .. ":" .. tostring(t.d)
print(t.e)
return t.e