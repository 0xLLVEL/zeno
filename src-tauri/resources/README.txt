Drop build outputs here before `npm run tauri:build`:

  zeno_inject.dll        from zeno-core/build/
  zeno_offsets.json      from zeno-core/config/

In development the loader also looks in:
  <cwd>/zeno-core/build/Release/zeno_inject.dll
  <cwd>/zeno-core/build/zeno_inject.dll
