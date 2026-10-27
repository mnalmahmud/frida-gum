#pragma once

#include "core.hpp"

#include <cstring>
#include <exception>
#include <functional>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace Gum {

class MatchPattern final {
public:
  explicit MatchPattern(const char* pattern)
      : handle_(gum_match_pattern_new_from_string(pattern)) {}
  explicit MatchPattern(const std::string& pattern) : MatchPattern(pattern.c_str()) {}
  ~MatchPattern() { if (handle_) gum_match_pattern_unref(handle_); }
  MatchPattern(const MatchPattern& other)
      : handle_(other.handle_ ? gum_match_pattern_ref(other.handle_) : nullptr) {}
  MatchPattern(MatchPattern&& other) noexcept
      : handle_(std::exchange(other.handle_, nullptr)) {}
  MatchPattern& operator=(MatchPattern other) noexcept {
    std::swap(handle_, other.handle_);
    return *this;
  }
  [[nodiscard]] explicit operator bool() const noexcept { return handle_ != nullptr; }
  [[nodiscard]] GumMatchPattern* get_handle() const noexcept { return handle_; }
  [[nodiscard]] std::size_t size() const noexcept {
    return handle_ ? gum_match_pattern_get_size(handle_) : 0;
  }
private:
  GumMatchPattern* handle_ = nullptr;
};

struct Memory {
  using Protection = GumPageProtection;
  struct Match { GumAddress address; std::size_t size; };

  // A failed read returns nullopt. Reads may be partial.
  [[nodiscard]] static std::optional<std::vector<std::byte>> read(
      const void* address, std::size_t length) {
    if (length == 0) return std::vector<std::byte>{};
    gsize count = 0;
    auto* raw = gum_memory_read(address, length, &count);
    if (!raw) return std::nullopt;
    std::vector<std::byte> result(count);
    if (count != 0) std::memcpy(result.data(), raw, count);
    g_free(raw);
    return result;
  }

  [[nodiscard]] static bool write(void* address, std::span<const std::byte> data) {
    if (data.empty()) return true;
    return gum_memory_write(address,
        reinterpret_cast<const guint8*>(data.data()), data.size()) != FALSE;
  }
  template <typename T> requires std::is_trivially_copyable_v<T>
  [[nodiscard]] static bool write(void* address, const T& value) {
    return write(address, std::as_bytes(std::span(&value, 1)));
  }

  [[nodiscard]] static void* alloc(std::size_t size,
      Protection protection = GUM_PAGE_RW) {
    if (size == 0) return nullptr;
    return gum_memory_allocate(nullptr, size, gum_query_page_size(), protection);
  }
  template <typename T> requires (!std::is_void_v<T>)
  [[nodiscard]] static T* alloc_n(std::size_t count,
      Protection protection = GUM_PAGE_RW) {
    if (count > std::numeric_limits<std::size_t>::max() / sizeof(T))
      return nullptr;
    return static_cast<T*>(alloc(count * sizeof(T), protection));
  }
  [[nodiscard]] static bool free(void* address, std::size_t size) {
    return gum_memory_free(address, size) != FALSE;
  }
  [[nodiscard]] static bool protect(void* address, std::size_t size,
      Protection protection) {
    return gum_try_mprotect(address, size, protection) != FALSE;
  }

  // Gum provides a writable mapping which may differ from the target pointer.
  template <typename F>
  [[nodiscard]] static bool patch_code(void* address, std::size_t size,
      F&& apply) {
    using Callback = std::remove_reference_t<F>;
    Callback& callback = apply;
    std::exception_ptr error;
    struct State { Callback* callback; std::exception_ptr* error; } state{
      &callback, &error
    };
    const auto ok = gum_memory_patch_code(address, size,
        [](gpointer writable, gpointer data) {
          auto& s = *static_cast<State*>(data);
          try { std::invoke(*s.callback, writable); }
          catch (...) { *s.error = std::current_exception(); }
        }, &state);
    if (error) std::rethrow_exception(error);
    return ok != FALSE;
  }

  // Returning false from the callback stops enumeration.
  template <typename F>
  static void scan(GumMemoryRange range, const MatchPattern& pattern, F&& on_match) {
    if (!pattern) return;
    using Callback = std::remove_reference_t<F>;
    Callback& callback = on_match;
    std::exception_ptr error;
    struct State { Callback* callback; std::exception_ptr* error; } state{
      &callback, &error
    };
    gum_memory_scan(&range, pattern.get_handle(),
        [](GumAddress address, gsize size, gpointer data) -> gboolean {
          auto& s = *static_cast<State*>(data);
          if (*s.error) return FALSE;
          try {
            if constexpr (std::is_same_v<std::invoke_result_t<Callback&, Match>, bool>)
              return std::invoke(*s.callback, Match{address, size}) ? TRUE : FALSE;
            else {
              std::invoke(*s.callback, Match{address, size});
              return TRUE;
            }
          } catch (...) { *s.error = std::current_exception(); return FALSE; }
        }, &state);
    if (error) std::rethrow_exception(error);
  }
};

class ScopedAllocation final {
public:
  explicit ScopedAllocation(std::size_t size,
      GumPageProtection protection = GUM_PAGE_RW)
      : address_(Memory::alloc(size, protection)), size_(size) {}
  ~ScopedAllocation() { reset(); }
  ScopedAllocation(const ScopedAllocation&) = delete;
  ScopedAllocation& operator=(const ScopedAllocation&) = delete;
  ScopedAllocation(ScopedAllocation&& other) noexcept
      : address_(std::exchange(other.address_, nullptr)),
        size_(std::exchange(other.size_, 0)) {}
  ScopedAllocation& operator=(ScopedAllocation&& other) noexcept {
    if (this != &other) {
      reset();
      address_ = std::exchange(other.address_, nullptr);
      size_ = std::exchange(other.size_, 0);
    }
    return *this;
  }
  [[nodiscard]] void* data() const noexcept { return address_; }
  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  [[nodiscard]] explicit operator bool() const noexcept { return address_ != nullptr; }
  void reset() noexcept {
    if (address_) (void)Memory::free(address_, size_);
    address_ = nullptr;
    size_ = 0;
  }
private:
  void* address_ = nullptr;
  std::size_t size_ = 0;
};

} // namespace Gum
