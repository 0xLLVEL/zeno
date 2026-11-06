export const luauLanguage = {
  defaultToken: "",
  tokenPostfix: ".luau",

  keywords: [
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
    "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true",
    "until", "while", "continue", "export", "type",
  ],

  builtins: [
    "game", "workspace", "script", "plugin", "shared", "print", "warn", "error",
    "assert", "pcall", "xpcall", "tostring", "tonumber", "type", "typeof", "pairs",
    "ipairs", "next", "select", "setmetatable", "getmetatable", "rawget", "rawset",
    "rawequal", "rawlen", "unpack", "require", "tick", "time", "wait", "task",
    "spawn", "delay", "Instance", "Vector3", "Vector2", "CFrame", "Color3",
    "UDim", "UDim2", "Ray", "Region3", "Rect", "Enum", "task.wait", "task.spawn",
    "task.delay", "task.defer", "gcinfo", "collectgarbage", "string", "table",
    "math", "os", "coroutine", "utf8", "bit32", "debug",
  ],

  symbols: /[=><!~?:&|+\-*/^%]+/,
  escapes: /\\(?:[abfnrtv\\"']|x[0-9A-Fa-f]{1,4}|u[0-9A-Fa-f]{4}|[0-9]{1,3})/,

  tokenizer: {
    root: [
      [/[a-zA-Z_]\w*/, {
        cases: {
          "@keywords": "keyword",
          "@builtins": "type.identifier",
          "@default": "identifier",
        },
      }],
      { include: "@whitespace" },
      [/[{}()\[\]]/, "@brackets"],
      [/[<>](?!@symbols)/, "@brackets"],
      [/@symbols/, { cases: { "@operators": "operator", "@default": "" } }],
      [/\d*\.\d+([eE][-+]?\d+)?/, "number.float"],
      [/(0[xX][0-9a-fA-F]+)/, "number.hex"],
      [/\d+/, "number"],
      [/[;,.]/, "delimiter"],
      [/"([^"\\]|\\.)*$/, "string.invalid"],
      [/'([^'\\]|\\.)*$/, "string.invalid"],
      [/"/, "string", "@string_double"],
      [/'/, "string", "@string_single"],
      [/\[\[/, "string", "@string_long"],
      [/--\[\[/, "comment", "@comment_long"],
      [/--.*$/, "comment"],
    ],

    whitespace: [[/[ \t\r\n]+/, ""]],

    comment_long: [
      [/\]\]/, "comment", "@pop"],
      [/./, "comment"],
    ],

    string_double: [
      [/[^\\"]+/, "string"],
      [/@escapes/, "string.escape"],
      [/\\./, "string.escape.invalid"],
      [/"/, "string", "@pop"],
    ],

    string_single: [
      [/[^\\']+/, "string"],
      [/@escapes/, "string.escape"],
      [/\\./, "string.escape.invalid"],
      [/'/, "string", "@pop"],
    ],

    string_long: [
      [/\]\]/, "string", "@pop"],
      [/./, "string"],
    ],
  },

  operators: [
    "+", "-", "*", "/", "%", "^", "#", "==", "~=", "<=", ">=", "<", ">", "=",
    "..", "...", "and", "or", "not",
  ],
};

export const zinTheme = {
  base: "vs-dark" as const,
  inherit: true,
  rules: [
    { token: "comment", foreground: "565270", fontStyle: "italic" },
    { token: "keyword", foreground: "a48bff" },
    { token: "identifier", foreground: "e6e6f0" },
    { token: "type.identifier", foreground: "4fd1c5" },
    { token: "string", foreground: "9ae6b4" },
    { token: "string.escape", foreground: "f6ad55" },
    { token: "number", foreground: "f6ad55" },
    { token: "number.hex", foreground: "f6ad55" },
    { token: "operator", foreground: "ff8fab" },
    { token: "delimiter", foreground: "8b8b9e" },
    { token: "brackets", foreground: "8b8b9e" },
  ],
  colors: {
    "editor.background": "#0d0d14",
    "editor.foreground": "#e6e6f0",
    "editorLineNumber.foreground": "#3a3a4d",
    "editorLineNumber.activeForeground": "#7c5cff",
    "editorCursor.foreground": "#7c5cff",
    "editor.selectionBackground": "#2a2150",
    "editor.lineHighlightBackground": "#14141f",
    "editorIndentGuide.background1": "#1a1a26",
    "editorWidget.background": "#12121a",
    "editorWidget.border": "#22222f",
    "editorSuggestWidget.background": "#12121a",
    "editorSuggestWidget.selectedBackground": "#221c47",
    "scrollbarSlider.background": "#2a2a3a66",
    "scrollbarSlider.hoverBackground": "#3a3a4a88",
    "minimap.background": "#0b0b10",
  },
};
