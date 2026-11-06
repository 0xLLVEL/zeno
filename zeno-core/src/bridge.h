#pragma once
#include <string>
#include <string_view>
#include <functional>

namespace zeno::bridge {

// Spawns the pipe client threads. Idempotent.
void start(std::function<void(std::string_view)> on_script);

// Thread-safe; queues a line for the UI console.
void out(std::string_view line);
void out_err(std::string_view line);
void out_warn(std::string_view line);

bool connected();

} // namespace zeno::bridge
