import { useMemo, useState } from "react";
import { useZeno } from "../store";
import type { HubScript } from "../types";

const HUB: HubScript[] = [
  {
    id: "inf-yield",
    name: "Infinite Yield",
    author: "EdgeWorks",
    description: "Full admin command suite — 300+ commands, GUI panel.",
    tags: ["admin", "gui"],
    source: `-- Infinite Yield (Zeno stub)
loadstring(game:HttpGet("https://raw.githubusercontent.com/EdgeIY/infiniteyield/master/source"))()`,
  },
  {
    id: "dex",
    name: "Dex Explorer",
    author: "LorekeeperZinnia",
    description: "Runtime instance explorer with property editor.",
    tags: ["explorer", "debug"],
    source: `-- Dex Explorer
loadstring(game:HttpGet("https://raw.githubusercontent.com/LorekeeperZinnia/Dex/main/source"))()`,
  },
  {
    id: "esp",
    name: "Universal ESP",
    author: "zeno",
    description: "Box + name + health ESP for players and NPCs.",
    tags: ["esp", "visual"],
    source: `-- Universal ESP (Zeno)
local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local cam = workspace.CurrentCamera

local box = Drawing.new("Square")
box.Thickness = 1
box.Color = Color3.fromRGB(124, 92, 255)
box.Filled = false

local name = Drawing.new("Text")
name.Size = 14
name.Center = true
name.Outline = true
name.Color = Color3.new(1, 1, 1)

RunService.RenderStepped:Connect(function()
  for _, plr in ipairs(Players:GetPlayers()) do
    if plr == Players.LocalPlayer then continue end
    local char = plr.Character
    local hrp = char and char:FindFirstChild("HumanoidRootPart")
    if not hrp then continue end
    local pos, onScreen = cam:WorldToViewportPoint(hrp.Position)
    if not onScreen then
      box.Visible = false
      name.Visible = false
      continue
    end
    box.Visible = true
    name.Visible = true
    box.Size = Vector2.new(40, 60)
    box.Position = Vector2.new(pos.X - 20, pos.Y - 30)
    name.Position = Vector2.new(pos.X, pos.Y - 40)
    name.Text = plr.Name
  end
end)`,
  },
  {
    id: "speed",
    name: "Speed & Jump",
    author: "zeno",
    description: "Configurable walkspeed and jump power with toggle.",
    tags: ["movement"],
    source: `-- Speed & Jump
local plr = game.Players.LocalPlayer
local char = plr.Character or plr.CharacterAdded:Wait()
local hum = char:WaitForChild("Humanoid")

hum.WalkSpeed = 64
hum.JumpPower = 80
hum.UseJumpPower = true
print("speed: 64 / jump: 80")`,
  },
  {
    id: "fly",
    name: "Simple Fly",
    author: "zeno",
    description: "WASD flight with Space/Shift for vertical.",
    tags: ["movement", "fun"],
    source: `-- Simple Fly
local Players = game:GetService("Players")
local UIS = game:GetService("UserInputService")
local RunService = game:GetService("RunService")

local plr = Players.LocalPlayer
local char = plr.Character or plr.CharacterAdded:Wait()
local hrp = char:WaitForChild("HumanoidRootPart")

local speed = 2
local keys = {}
UIS.InputBegan:Connect(function(i) keys[i.KeyCode] = true end)
UIS.InputEnded:Connect(function(i) keys[i.KeyCode] = false end)

local bv = Instance.new("BodyVelocity")
bv.MaxForce = Vector3.new(1e5, 1e5, 1e5)
bv.Parent = hrp

RunService.RenderStepped:Connect(function()
  local dir = Vector3.zero
  local cam = workspace.CurrentCamera.CFrame
  if keys[Enum.KeyCode.W] then dir += cam.LookVector end
  if keys[Enum.KeyCode.S] then dir -= cam.LookVector end
  if keys[Enum.KeyCode.A] then dir -= cam.RightVector end
  if keys[Enum.KeyCode.D] then dir += cam.RightVector end
  if keys[Enum.KeyCode.Space] then dir += Vector3.yAxis end
  if keys[Enum.KeyCode.LeftShift] then dir -= Vector3.yAxis end
  bv.Velocity = dir.Magnitude > 0 and dir.Unit * speed * 30 or Vector3.zero
end)`,
  },
];

export function ScriptHub() {
  const { addTab, log } = useZeno();
  const [q, setQ] = useState("");
  const [tag, setTag] = useState<string>("all");

  const tags = useMemo(() => ["all", ...new Set(HUB.flatMap((s) => s.tags))], []);
  const list = useMemo(
    () =>
      HUB.filter(
        (s) =>
          (tag === "all" || s.tags.includes(tag)) &&
          (!q ||
            s.name.toLowerCase().includes(q.toLowerCase()) ||
            s.description.toLowerCase().includes(q.toLowerCase())),
      ),
    [q, tag],
  );

  return (
    <div className="pane hub-pane">
      <div className="hub-head">
        <h2>Script Hub</h2>
        <input
          className="hub-search"
          placeholder="search scripts…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
      </div>

      <div className="hub-tags">
        {tags.map((t) => (
          <button key={t} className={`chip ${tag === t ? "on" : ""}`} onClick={() => setTag(t)}>
            {t}
          </button>
        ))}
      </div>

      <div className="hub-grid">
        {list.map((s) => (
          <div key={s.id} className="hub-card">
            <div className="hub-card-top">
              <span className="hub-name">{s.name}</span>
              <span className="hub-author">@{s.author}</span>
            </div>
            <p className="hub-desc">{s.description}</p>
            <div className="hub-card-foot">
              <div className="hub-card-tags">
                {s.tags.map((t) => (
                  <span key={t} className="tag">
                    {t}
                  </span>
                ))}
              </div>
              <div className="hub-actions">
                <button
                  className="mini"
                  onClick={() => {
                    addTab(`${s.id}.lua`, s.source);
                    log("ok", `loaded "${s.name}" into a new tab`);
                  }}
                >
                  open
                </button>
                <button
                  className="mini accent"
                  onClick={() => {
                    void navigator.clipboard.writeText(s.source);
                    log("info", `copied "${s.name}" to clipboard`);
                  }}
                >
                  copy
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
