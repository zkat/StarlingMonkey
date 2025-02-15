#include "host_api.h"
#include "bindings/bindings.h"
#include "handles.h"
#include <filesystem>
#include <map>
#include <string>
#include <tuple>
#include <vector>

static std::optional<wasi_clocks_monotonic_clock_own_pollable_t> immediately_ready;

size_t poll_handles(vector<WASIHandle<host_api::Pollable>::Borrowed> handles) {
  auto list = list_borrow_pollable_t{handles.data(), handles.size()};
  bindings_list_u32_t result{nullptr, 0};
  wasi_io_poll_poll(&list, &result);
  MOZ_ASSERT(result.len > 0);
  const auto ready_index = result.ptr[0];
  free(result.ptr);
  return ready_index;
}

size_t api::AsyncTask::select(std::vector<AsyncTask *> &tasks) {
  auto count = tasks.size();
  std::vector<WASIHandle<host_api::Pollable>::Borrowed> handles;

  for (size_t idx = 0; idx < count; ++idx) {
    auto *task = tasks.at(idx);
    auto id = task->id();

    if (id == IMMEDIATE_TASK_HANDLE) {
      if (handles.size() > 0) {
        if (!immediately_ready) {
          immediately_ready = wasi_clocks_monotonic_clock_subscribe_duration(0);
        }
        handles.emplace_back(immediately_ready.value().__handle);
        size_t len = handles.size();
        size_t ready_index = poll_handles(std::move(handles));
        if (ready_index <= len - 1) {
          return ready_index;
        }
      }
      return idx;
    }
    handles.emplace_back(id);
  }

  return poll_handles(std::move(handles));
}

namespace host_api {

namespace {

template <typename T> HostString to_host_string(T str) {
  return {JS::UniqueChars(reinterpret_cast<char *>(str.ptr)), str.len};
}

auto bindings_string_to_host_string = to_host_string<bindings_string_t>;

template <typename T> T from_string_view(std::string_view str) {
  return T{
      .ptr = (uint8_t *)str.data(),
      .len = str.size(),
  };
}

auto string_view_to_world_string = from_string_view<bindings_string_t>;

HostString scheme_to_string(const wasi_http_types_scheme_t &scheme) {
  if (scheme.tag == WASI_HTTP_TYPES_SCHEME_HTTP) {
    return {"http"};
  }
  if (scheme.tag == WASI_HTTP_TYPES_SCHEME_HTTPS) {
    return {"https"};
  }
  return to_host_string(scheme.val.other);
}

void dump_io_error(wasi_io_streams_stream_error_t err) {
#ifdef DEBUG
  MOZ_ASSERT(err.tag == WASI_IO_STREAMS_STREAM_ERROR_LAST_OPERATION_FAILED);
  bindings_string_t debug_str;
  wasi_io_error_method_error_to_debug_string({err.val.last_operation_failed.__handle}, &debug_str);
  DBG("WASI IO Error: %.*s\n", (int)debug_str.len, reinterpret_cast<const char *>(debug_str.ptr));
#endif
}

} // namespace

Result<HostBytes> Random::get_bytes(size_t num_bytes) {
  Result<HostBytes> res;

  bindings_list_u8_t list{};
  wasi_random_random_get_random_bytes(num_bytes, &list);
  auto ret = HostBytes{
      std::unique_ptr<uint8_t[]>{list.ptr},
      list.len,
  };
  res.emplace(std::move(ret));

  return res;
}

Result<uint32_t> Random::get_u32() {
  return Result<uint32_t>::ok(wasi_random_random_get_random_u64());
}

uint64_t MonotonicClock::now() { return wasi_clocks_monotonic_clock_now(); }

uint64_t MonotonicClock::resolution() { return wasi_clocks_monotonic_clock_resolution(); }

int32_t MonotonicClock::subscribe(const uint64_t when, const bool absolute) {
  if (absolute) {
    return wasi_clocks_monotonic_clock_subscribe_instant(when).__handle;
  } else {
    return wasi_clocks_monotonic_clock_subscribe_duration(when).__handle;
  }
}

void MonotonicClock::unsubscribe(const int32_t handle_id) {
  wasi_io_poll_pollable_drop_own(own_pollable_t{handle_id});
}

vector<std::string> environment_get_arguments() {
  bindings_list_string_t raw_args = {};
  wasi_cli_environment_get_arguments(&raw_args);
  std::vector<std::string> args = {};
  for (int i = 0; i < raw_args.len; i++) {
    args.push_back(std::string(reinterpret_cast<char *>(raw_args.ptr[i].ptr), raw_args.ptr[i].len));
  }
  return args;
}

HttpHeaders::HttpHeaders(std::unique_ptr<HandleState> state)
    : HttpHeadersReadOnly(std::move(state)) {}

HttpHeaders::HttpHeaders() {
  handle_state_ = std::make_unique<WASIHandle<HttpHeaders>>(wasi_http_types_constructor_fields());
}

Result<HttpHeaders *> HttpHeaders::FromEntries(vector<tuple<HostString, HostString>> &entries) {
  std::vector<bindings_tuple2_field_key_field_value_t> pairs;
  pairs.reserve(entries.size());

  for (const auto &[name, value] : entries) {
    pairs.emplace_back(from_string_view<field_key>(name), from_string_view<field_value>(value));
  }

  bindings_list_tuple2_field_key_field_value_t tuples{pairs.data(), entries.size()};

  wasi_http_types_own_fields_t ret;
  wasi_http_types_header_error_t err;
  if (!wasi_http_types_static_fields_from_list(&tuples, &ret, &err)) {
    // TODO: handle `err`
    return Result<HttpHeaders *>::err(154);
  }

  auto headers = new HttpHeaders(std::make_unique<WASIHandle<HttpHeaders>>(ret));
  return Result<HttpHeaders *>::ok(headers);
}

HttpHeaders::HttpHeaders(const HttpHeadersReadOnly &headers) : HttpHeadersReadOnly(nullptr) {
  Borrow<HttpHeaders> borrow(headers.handle_state_.get());
  auto handle = wasi_http_types_method_fields_clone(borrow);
  this->handle_state_ = std::unique_ptr<HandleState>(new WASIHandle<HttpHeaders>(handle));
}

// We currently only guard against a single request header, instead of the full list in
// https://fetch.spec.whatwg.org/#forbidden-request-header.
static const std::vector forbidden_request_headers = {
    "host",
};

// We currently only guard against a single response header, instead of the full list in
// https://fetch.spec.whatwg.org/#forbidden-request-header.
static const std::vector forbidden_response_headers = {
    "host",
};

const std::vector<const char *> &HttpHeaders::get_forbidden_request_headers() {
  return forbidden_request_headers;
}

const std::vector<const char *> &HttpHeaders::get_forbidden_response_headers() {
  return forbidden_response_headers;
}

HttpHeaders *HttpHeadersReadOnly::clone() { return new HttpHeaders(*this); }

Result<vector<tuple<HostString, HostString>>> HttpHeadersReadOnly::entries() const {
  Result<vector<tuple<HostString, HostString>>> res;

  bindings_list_tuple2_field_key_field_value_t entries;
  Borrow<HttpHeaders> borrow(this->handle_state_.get());
  wasi_http_types_method_fields_entries(borrow, &entries);

  vector<tuple<HostString, HostString>> entries_vec;
  for (int i = 0; i < entries.len; i++) {
    auto key = entries.ptr[i].f0;
    auto value = entries.ptr[i].f1;
    entries_vec.emplace_back(to_host_string(key), to_host_string(value));
  }
  // Free the outer list, but not the entries themselves.
  free(entries.ptr);
  res.emplace(std::move(entries_vec));

  return res;
}

Result<vector<HostString>> HttpHeadersReadOnly::names() const {
  Result<vector<HostString>> res;

  bindings_list_tuple2_field_key_field_value_t entries;
  Borrow<HttpHeaders> borrow(this->handle_state_.get());
  wasi_http_types_method_fields_entries(borrow, &entries);

  vector<HostString> names;
  names.reserve(entries.len);
  for (int i = 0; i < entries.len; i++) {
    names.emplace_back(bindings_string_to_host_string(entries.ptr[i].f0));
  }
  // Free the outer list, but not the entries themselves.
  free(entries.ptr);
  res.emplace(std::move(names));

  return res;
}

Result<optional<vector<HostString>>> HttpHeadersReadOnly::get(string_view name) const {
  Result<optional<vector<HostString>>> res;

  bindings_list_field_value_t values;
  auto hdr = string_view_to_world_string(name);
  Borrow<HttpHeaders> borrow(this->handle_state_.get());
  wasi_http_types_method_fields_get(borrow, &hdr, &values);

  if (values.len > 0) {
    std::vector<HostString> names;
    names.reserve(values.len);
    for (int i = 0; i < values.len; i++) {
      names.emplace_back(to_host_string<field_value>(values.ptr[i]));
    }
    // Free the outer list, but not the values themselves.
    free(values.ptr);
    res.emplace(std::move(names));
  } else {
    res.emplace(std::nullopt);
  }

  return res;
}

Result<bool> HttpHeadersReadOnly::has(string_view name) const {
  auto hdr = string_view_to_world_string(name);
  Borrow<HttpHeaders> borrow(this->handle_state_.get());
  return Result<bool>::ok(wasi_http_types_method_fields_has(borrow, &hdr));
}

Result<Void> HttpHeaders::set(string_view name, string_view value) {
  auto hdr = from_string_view<field_key>(name);
  auto val = from_string_view<field_value>(value);
  bindings_list_field_value_t host_values{&val, 1};
  Borrow<HttpHeaders> borrow(this->handle_state_.get());

  wasi_http_types_header_error_t err;
  if (!wasi_http_types_method_fields_set(borrow, &hdr, &host_values, &err)) {
    // TODO: handle `err`
    return Result<Void>::err(154);
  }

  return {};
}

Result<Void> HttpHeaders::append(string_view name, string_view value) {
  auto hdr = from_string_view<field_key>(name);
  auto val = from_string_view<field_value>(value);
  Borrow<HttpHeaders> borrow(this->handle_state_.get());

  // TODO: properly handle `err`
  wasi_http_types_header_error_t err;
  if (!wasi_http_types_method_fields_append(borrow, &hdr, &val, &err)) {
    switch (err.tag) {
    case WASI_HTTP_TYPES_HEADER_ERROR_INVALID_SYNTAX:
    case WASI_HTTP_TYPES_HEADER_ERROR_FORBIDDEN:
      return Result<Void>::err(154);
    case WASI_HTTP_TYPES_HEADER_ERROR_IMMUTABLE:
      MOZ_ASSERT_UNREACHABLE("Headers should not be immutable");
      [[fallthrough]];
    default:
      MOZ_ASSERT_UNREACHABLE("Unknown header error type");
    }
  }

  return {};
}

Result<Void> HttpHeaders::remove(string_view name) {
  auto hdr = string_view_to_world_string(name);
  Borrow<HttpHeaders> borrow(this->handle_state_.get());

  wasi_http_types_header_error_t err;
  if (!wasi_http_types_method_fields_delete(borrow, &hdr, &err)) {
    // TODO: handle `err`
    return Result<Void>::err(154);
  }

  return {};
}

// TODO: convert to `Result`
string_view HttpRequestResponseBase::url() {
  if (_url) {
    return string_view(*_url);
  }

  Borrow<HttpIncomingRequest> borrow(handle_state_.get());

  wasi_http_types_scheme_t scheme;
  bool success;
  success = wasi_http_types_method_incoming_request_scheme(borrow, &scheme);
  MOZ_RELEASE_ASSERT(success);

  bindings_string_t authority;
  success = wasi_http_types_method_incoming_request_authority(borrow, &authority);
  MOZ_RELEASE_ASSERT(success);

  bindings_string_t path;
  success = wasi_http_types_method_incoming_request_path_with_query(borrow, &path);
  MOZ_RELEASE_ASSERT(success);

  HostString scheme_str = scheme_to_string(scheme);
  _url = new std::string(scheme_str.ptr.release(), scheme_str.len);
  _url->append("://");
  _url->append(string_view(bindings_string_to_host_string(authority)));
  _url->append(string_view(bindings_string_to_host_string(path)));

  return string_view(*_url);
}

bool write_to_outgoing_body(Borrow<OutputStream> borrow, const uint8_t *ptr, const size_t len) {
  // The write call doesn't mutate the buffer; the cast is just for the
  // generated bindings.
  bindings_list_u8_t list{const_cast<uint8_t *>(ptr), len};
  wasi_io_streams_stream_error_t err;
  // TODO: proper error handling.
  bool success = wasi_io_streams_method_output_stream_write(borrow, &list, &err);
  if (!success) {
    dump_io_error(err);
    return false;
  }
  return true;
}

HttpOutgoingBody::HttpOutgoingBody(std::unique_ptr<HandleState> state) : Pollable() {
  handle_state_ = std::move(state);
}
Result<uint64_t> HttpOutgoingBody::capacity() {
  if (!valid()) {
    // TODO: proper error handling for all 154 error codes.
    return Result<uint64_t>::err(154);
  }

  auto *state = static_cast<OutgoingBodyHandle *>(this->handle_state_.get());
  Borrow<OutputStream> borrow(state->stream_handle_);
  uint64_t capacity = 0;
  wasi_io_streams_stream_error_t err;
  if (!wasi_io_streams_method_output_stream_check_write(borrow, &capacity, &err)) {
    dump_io_error(err);
    return Result<uint64_t>::err(154);
  }
  return Result<uint64_t>::ok(capacity);
}

void HttpOutgoingBody::write(const uint8_t *bytes, size_t len) {
  MOZ_ASSERT(capacity().unwrap() >= len);

  auto *state = static_cast<OutgoingBodyHandle *>(this->handle_state_.get());
  Borrow<OutputStream> borrow(state->stream_handle_);
  MOZ_RELEASE_ASSERT(write_to_outgoing_body(borrow, bytes, len));
}

class BodyWriteAllTask final : public api::AsyncTask {
  HttpOutgoingBody *outgoing_body_;
  PollableHandle outgoing_pollable_;

  api::TaskCompletionCallback cb_;
  Heap<JSObject *> cb_receiver_;
  HostBytes bytes_;
  size_t offset_ = 0;

public:
  explicit BodyWriteAllTask(HttpOutgoingBody *outgoing_body, HostBytes bytes,
                            api::TaskCompletionCallback completion_callback,
                            HandleObject callback_receiver)
      : outgoing_body_(outgoing_body), cb_(completion_callback), cb_receiver_(callback_receiver),
        bytes_(std::move(bytes)) {
    outgoing_pollable_ = outgoing_body_->subscribe().unwrap();
  }

  [[nodiscard]] bool run(api::Engine *engine) override {
    MOZ_ASSERT(offset_ < bytes_.len);
    while (true) {
      auto res = outgoing_body_->capacity();
      if (res.is_err()) {
        return false;
      }
      uint64_t capacity = res.unwrap();
      if (capacity == 0) {
        engine->queue_async_task(this);
        return true;
      }

      auto bytes_to_write = std::min(bytes_.len - offset_, static_cast<size_t>(capacity));
      outgoing_body_->write(bytes_.ptr.get() + offset_, bytes_to_write);
      offset_ += bytes_to_write;
      MOZ_ASSERT(offset_ <= bytes_.len);
      if (offset_ == bytes_.len) {
        bytes_.ptr.reset();
        RootedObject receiver(engine->cx(), cb_receiver_);
        bool result = cb_(engine->cx(), receiver);
        cb_ = nullptr;
        cb_receiver_ = nullptr;
        return result;
      }
    }
  }

  [[nodiscard]] bool cancel(api::Engine *engine) override {
    MOZ_ASSERT_UNREACHABLE("BodyWriteAllTask's semantics don't allow for cancellation");
    return true;
  }

  [[nodiscard]] int32_t id() override { return outgoing_pollable_; }

  void trace(JSTracer *trc) override {
    JS::TraceEdge(trc, &cb_receiver_, "BodyWriteAllTask completion callback receiver");
  }
};

Result<Void> HttpOutgoingBody::write_all(api::Engine *engine, HostBytes bytes,
                                         api::TaskCompletionCallback callback,
                                         HandleObject cb_receiver) {
  if (!valid()) {
    // TODO: proper error handling for all 154 error codes.
    return Result<Void>::err(154);
  }
  engine->queue_async_task(new BodyWriteAllTask(this, std::move(bytes), callback, cb_receiver));
  return {};
}

class BodyAppendTask final : public api::AsyncTask {
  enum class State {
    BlockedOnBoth,
    BlockedOnIncoming,
    BlockedOnOutgoing,
    Ready,
    Done,
  };

  HttpIncomingBody *incoming_body_;
  HttpOutgoingBody *outgoing_body_;
  PollableHandle incoming_pollable_;
  PollableHandle outgoing_pollable_;

  api::TaskCompletionCallback cb_;
  Heap<JSObject *> cb_receiver_;
  State state_;

  void set_state(JSContext *cx, const State state) {
    MOZ_ASSERT(state_ != State::Done);
    state_ = state;
    if (state == State::Done && cb_) {
      RootedObject receiver(cx, cb_receiver_);
      cb_(cx, receiver);
      cb_ = nullptr;
      cb_receiver_ = nullptr;
    }
  }

public:
  explicit BodyAppendTask(api::Engine *engine, HttpIncomingBody *incoming_body,
                          HttpOutgoingBody *outgoing_body,
                          api::TaskCompletionCallback completion_callback,
                          HandleObject callback_receiver)
      : incoming_body_(incoming_body), outgoing_body_(outgoing_body), cb_(completion_callback),
        cb_receiver_(callback_receiver), state_(State::BlockedOnBoth) {
    incoming_pollable_ = incoming_body_->subscribe().unwrap();
    outgoing_pollable_ = outgoing_body_->subscribe().unwrap();
  }

  [[nodiscard]] bool run(api::Engine *engine) override {
    // If run is called while we're blocked on the incoming stream, that means that stream's
    // pollable has resolved, so the stream must be ready.
    if (state_ == State::BlockedOnBoth || state_ == State::BlockedOnIncoming) {
      auto res = incoming_body_->read(0);
      MOZ_ASSERT(!res.is_err());
      auto [done, _] = std::move(res.unwrap());
      if (done) {
        set_state(engine->cx(), State::Done);
        return true;
      }
      set_state(engine->cx(), State::BlockedOnOutgoing);
    }

    MOZ_ASSERT(state_ == State::BlockedOnOutgoing);
    auto res = outgoing_body_->capacity();
    if (res.is_err()) {
      return false;
    }
    uint64_t capacity = res.unwrap();
    if (capacity > 0) {
      set_state(engine->cx(), State::Ready);
    } else {
      engine->queue_async_task(this);
      return true;
    }

    MOZ_ASSERT(state_ == State::Ready);

    // TODO: reuse a buffer for this loop
    do {
      auto res = incoming_body_->read(capacity);
      if (res.is_err()) {
        // TODO: proper error handling.
        return false;
      }
      auto [done, bytes] = std::move(res.unwrap());
      if (bytes.len == 0 && !done) {
        set_state(engine->cx(), State::BlockedOnIncoming);
        engine->queue_async_task(this);
        return true;
      }

      if (bytes.len > 0) {
        outgoing_body_->write(bytes.ptr.get(), bytes.len);
      }

      if (done) {
        set_state(engine->cx(), State::Done);
        return true;
      }

      auto capacity_res = outgoing_body_->capacity();
      if (capacity_res.is_err()) {
        // TODO: proper error handling.
        return false;
      }
      capacity = capacity_res.unwrap();
    } while (capacity > 0);

    set_state(engine->cx(), State::BlockedOnOutgoing);
    engine->queue_async_task(this);
    return true;
  }

  [[nodiscard]] bool cancel(api::Engine *engine) override {
    MOZ_ASSERT_UNREACHABLE("BodyAppendTask's semantics don't allow for cancellation");
    return true;
  }

  [[nodiscard]] int32_t id() override {
    if (state_ == State::BlockedOnBoth || state_ == State::BlockedOnIncoming) {
      return incoming_pollable_;
    }

    MOZ_ASSERT(state_ == State::BlockedOnOutgoing,
               "BodyAppendTask should only be queued if it's not known to be ready");
    return outgoing_pollable_;
  }

  void trace(JSTracer *trc) override {
    JS::TraceEdge(trc, &cb_receiver_, "BodyAppendTask completion callback receiver");
  }
};

Result<Void> HttpOutgoingBody::append(api::Engine *engine, HttpIncomingBody *other,
                                      api::TaskCompletionCallback callback,
                                      HandleObject callback_receiver) {
  engine->queue_async_task(new BodyAppendTask(engine, other, this, callback, callback_receiver));
  return {};
}

Result<Void> HttpOutgoingBody::close() {
  auto state = static_cast<OutgoingBodyHandle *>(handle_state_.get());
  // A blocking flush is required here to ensure that all buffered contents are
  // actually written before finishing the body.
  Borrow<OutputStream> borrow{state->stream_handle_};

  {
    wasi_io_streams_stream_error_t err;
    bool success = wasi_io_streams_method_output_stream_blocking_flush(borrow, &err);
    if (!success) {
      // TODO: validate that this condition applies if `content-length` bytes were written, and
      //  the host has auto-closed the body.
      MOZ_RELEASE_ASSERT(err.tag == WASI_IO_STREAMS_STREAM_ERROR_CLOSED);
    }
  }

  if (state->pollable_handle_ != INVALID_POLLABLE_HANDLE) {
    wasi_io_poll_pollable_drop_own(own_pollable_t{state->pollable_handle_});
  }
  wasi_io_streams_output_stream_drop_own({state->stream_handle_});

  {
    wasi_http_types_error_code_t err;
    wasi_http_types_static_outgoing_body_finish({state->take()}, nullptr, &err);
    // TODO: handle `err`
  }

  return {};
}
Result<PollableHandle> HttpOutgoingBody::subscribe() {
  auto state = static_cast<OutgoingBodyHandle *>(handle_state_.get());
  if (state->pollable_handle_ == INVALID_POLLABLE_HANDLE) {
    Borrow<OutputStream> borrow(state->stream_handle_);
    state->pollable_handle_ = wasi_io_streams_method_output_stream_subscribe(borrow).__handle;
  }
  return Result<PollableHandle>::ok(state->pollable_handle_);
}

void HttpOutgoingBody::unsubscribe() {
  auto state = static_cast<OutgoingBodyHandle *>(handle_state_.get());
  if (state->pollable_handle_ == INVALID_POLLABLE_HANDLE) {
    return;
  }
  wasi_io_poll_pollable_drop_own(own_pollable_t{state->pollable_handle_});
  state->pollable_handle_ = INVALID_POLLABLE_HANDLE;
}

static const char *http_method_names[9] = {"GET",     "HEAD",    "POST",  "PUT",  "DELETE",
                                           "CONNECT", "OPTIONS", "TRACE", "PATCH"};

wasi_http_types_method_t http_method_to_host(string_view method_str) {

  if (method_str.empty()) {
    return wasi_http_types_method_t{WASI_HTTP_TYPES_METHOD_GET};
  }

  auto method = method_str.begin();
  for (uint8_t i = 0; i < WASI_HTTP_TYPES_METHOD_OTHER; i++) {
    auto name = http_method_names[i];
    if (strcasecmp(method, name) == 0) {
      return wasi_http_types_method_t{i};
    }
  }

  auto val = bindings_string_t{reinterpret_cast<uint8_t *>(const_cast<char *>(method)),
                               method_str.length()};
  return wasi_http_types_method_t{WASI_HTTP_TYPES_METHOD_OTHER, {val}};
}

HttpOutgoingRequest::HttpOutgoingRequest(std::unique_ptr<HandleState> state) {
  this->handle_state_ = std::move(state);
}

HttpOutgoingRequest *HttpOutgoingRequest::make(string_view method_str, optional<HostString> url_str,
                                               std::unique_ptr<HttpHeadersReadOnly> headers) {
  bindings_string_t path_with_query;
  wasi_http_types_scheme_t scheme;
  bindings_string_t authority;

  bindings_string_t *maybe_path_with_query = nullptr;
  wasi_http_types_scheme_t *maybe_scheme = nullptr;
  bindings_string_t *maybe_authority = nullptr;

  if (url_str) {
    jsurl::SpecString val = url_str.value();
    jsurl::JSUrl *url = new_jsurl(&val);
    jsurl::SpecSlice protocol = jsurl::protocol(url);
    if (std::memcmp(protocol.data, "http:", protocol.len) == 0) {
      scheme.tag = WASI_HTTP_TYPES_SCHEME_HTTP;
    } else if (std::memcmp(protocol.data, "https:", protocol.len) == 0) {
      scheme.tag = WASI_HTTP_TYPES_SCHEME_HTTPS;
    } else {
      scheme.tag = WASI_HTTP_TYPES_SCHEME_OTHER;
      scheme.val = {const_cast<uint8_t *>(protocol.data), protocol.len - 1};
    }
    maybe_scheme = &scheme;

    jsurl::SpecSlice authority_slice = jsurl::authority(url);
    authority = {const_cast<uint8_t *>(authority_slice.data), authority_slice.len};
    maybe_authority = &authority;

    jsurl::SpecSlice path_with_query_slice = jsurl::path_with_query(url);
    path_with_query = {const_cast<uint8_t *>(path_with_query_slice.data),
                       path_with_query_slice.len};
    maybe_path_with_query = &path_with_query;
  }

  auto headers_handle = WASIHandle<HttpHeaders>::cast(headers->handle_state_.get())->take();
  auto handle = wasi_http_types_constructor_outgoing_request(headers_handle);
  {
    auto borrow = wasi_http_types_borrow_outgoing_request(handle);

    // TODO: error handling on result
    auto method = http_method_to_host(method_str);
    wasi_http_types_method_outgoing_request_set_method(borrow, &method);

    // TODO: error handling on result
    wasi_http_types_method_outgoing_request_set_scheme(borrow, maybe_scheme);

    // TODO: error handling on result
    wasi_http_types_method_outgoing_request_set_authority(borrow, maybe_authority);

    // TODO: error handling on result
    wasi_http_types_method_outgoing_request_set_path_with_query(borrow, maybe_path_with_query);
  }

  auto *state = new WASIHandle<HttpOutgoingRequest>(handle);
  auto *resp = new HttpOutgoingRequest(std::unique_ptr<HandleState>(state));

  return resp;
}

Result<string_view> HttpOutgoingRequest::method() { return Result<string_view>::ok(method_); }

Result<HttpHeadersReadOnly *> HttpOutgoingRequest::headers() {
  if (!headers_) {
    if (!valid()) {
      return Result<HttpHeadersReadOnly *>::err(154);
    }
    Borrow<HttpOutgoingRequest> borrow(handle_state_.get());
    auto res = wasi_http_types_method_outgoing_request_headers(borrow);
    headers_ =
        new HttpHeadersReadOnly(std::unique_ptr<HandleState>(new WASIHandle<HttpHeaders>(res)));
  }

  return Result<HttpHeadersReadOnly *>::ok(headers_);
}

Result<HttpOutgoingBody *> HttpOutgoingRequest::body() {
  typedef Result<HttpOutgoingBody *> Res;
  if (!this->body_) {
    outgoing_body_t body;
    Borrow<HttpOutgoingRequest> borrow(handle_state_.get());
    if (!wasi_http_types_method_outgoing_request_body(borrow, &body)) {
      return Res::err(154);
    }
    body_ = new HttpOutgoingBody(std::unique_ptr<HandleState>(new OutgoingBodyHandle(body)));
  }
  return Res::ok(body_);
}

Result<FutureHttpIncomingResponse *> HttpOutgoingRequest::send() {
  typedef Result<FutureHttpIncomingResponse *> Res;
  future_incoming_response_t ret;
  wasi_http_outgoing_handler_error_code_t err;
  auto request_handle = WASIHandle<HttpOutgoingRequest>::cast(handle_state_.get())->take();
  if (!wasi_http_outgoing_handler_handle(request_handle, nullptr, &ret, &err)) {
    return Res::err(154);
  }
  auto res = new FutureHttpIncomingResponse(
      std::unique_ptr<HandleState>(new WASIHandle<FutureHttpIncomingResponse>(ret)));
  return Result<FutureHttpIncomingResponse *>::ok(res);
}

void block_on_pollable_handle(PollableHandle handle) {
  wasi_io_poll_method_pollable_block({handle});
}

HttpIncomingBody::HttpIncomingBody(std::unique_ptr<HandleState> state) : Pollable() {
  handle_state_ = std::move(state);
}

Resource::~Resource() {
  if (handle_state_ != nullptr) {
    handle_state_ = nullptr;
  }
}

bool Resource::valid() const {
  return this->handle_state_ != nullptr && this->handle_state_->valid();
}

Result<HttpIncomingBody::ReadResult> HttpIncomingBody::read(uint32_t chunk_size) {
  typedef Result<ReadResult> Res;

  bindings_list_u8_t ret{};
  wasi_io_streams_stream_error_t err{};
  auto body_handle = IncomingBodyHandle::cast(handle_state_.get());
  auto borrow = Borrow<InputStream>(body_handle->stream_handle_);
  bool success = wasi_io_streams_method_input_stream_read(borrow, chunk_size, &ret, &err);
  if (!success) {
    if (err.tag == WASI_IO_STREAMS_STREAM_ERROR_CLOSED) {
      return Res::ok(ReadResult(true, nullptr, 0));
    }
    dump_io_error(err);
    return Res::err(154);
  }
  return Res::ok(ReadResult(false, unique_ptr<uint8_t[]>(ret.ptr), ret.len));
}

// TODO: implement
Result<Void> HttpIncomingBody::close() { return {}; }

Result<PollableHandle> HttpIncomingBody::subscribe() {
  auto body_handle = IncomingBodyHandle::cast(handle_state_.get());
  auto borrow = Borrow<InputStream>(body_handle->stream_handle_);
  auto pollable = wasi_io_streams_method_input_stream_subscribe(borrow);
  return Result<PollableHandle>::ok(pollable.__handle);
}
void HttpIncomingBody::unsubscribe() {
  auto state = static_cast<IncomingBodyHandle *>(handle_state_.get());
  if (state->pollable_handle_ == INVALID_POLLABLE_HANDLE) {
    return;
  }
  wasi_io_poll_pollable_drop_own(own_pollable_t{state->pollable_handle_});
  state->pollable_handle_ = INVALID_POLLABLE_HANDLE;
}

FutureHttpIncomingResponse::FutureHttpIncomingResponse(std::unique_ptr<HandleState> state) {
  handle_state_ = std::move(state);
}

Result<optional<HttpIncomingResponse *>> FutureHttpIncomingResponse::maybe_response() {
  typedef Result<optional<HttpIncomingResponse *>> Res;
  wasi_http_types_result_result_own_incoming_response_error_code_void_t res;
  Borrow<FutureHttpIncomingResponse> borrow(handle_state_.get());
  if (!wasi_http_types_method_future_incoming_response_get(borrow, &res)) {
    return Res::ok(std::nullopt);
  }

  MOZ_ASSERT(!res.is_err,
             "FutureHttpIncomingResponse::poll must not be called again after succeeding once");

  auto [is_err, val] = res.val.ok;
  if (is_err) {
    return Res::err(154);
  }

  auto state = new WASIHandle<HttpIncomingResponse>(val.ok);
  return Res::ok(new HttpIncomingResponse(std::unique_ptr<HandleState>(state)));
}

Result<PollableHandle> FutureHttpIncomingResponse::subscribe() {
  Borrow<FutureHttpIncomingResponse> borrow(handle_state_.get());
  auto pollable = wasi_http_types_method_future_incoming_response_subscribe(borrow);
  return Result<PollableHandle>::ok(pollable.__handle);
}
void FutureHttpIncomingResponse::unsubscribe() {
  // TODO: implement
}

HttpHeadersReadOnly::HttpHeadersReadOnly() { handle_state_ = nullptr; }

HttpHeadersReadOnly::HttpHeadersReadOnly(std::unique_ptr<HandleState> state) {
  handle_state_ = std::move(state);
}

Result<uint16_t> HttpIncomingResponse::status() {
  if (status_ == UNSET_STATUS) {
    if (!valid()) {
      return Result<uint16_t>::err(154);
    }
    auto borrow = Borrow<HttpIncomingResponse>(handle_state_.get());
    status_ = wasi_http_types_method_incoming_response_status(borrow);
  }
  return Result<uint16_t>::ok(status_);
}

HttpIncomingResponse::HttpIncomingResponse(std::unique_ptr<HandleState> state) {
  handle_state_ = std::move(state);
}

Result<HttpHeadersReadOnly *> HttpIncomingResponse::headers() {
  if (!headers_) {
    if (!valid()) {
      return Result<HttpHeadersReadOnly *>::err(154);
    }
    auto borrow = Borrow<HttpIncomingResponse>(handle_state_.get());
    auto res = wasi_http_types_method_incoming_response_headers(borrow);
    auto state = new WASIHandle<HttpHeaders>(res);
    headers_ = new HttpHeadersReadOnly(std::unique_ptr<HandleState>(state));
  }

  return Result<HttpHeadersReadOnly *>::ok(headers_);
}

Result<HttpIncomingBody *> HttpIncomingResponse::body() {
  if (!body_) {
    if (!valid()) {
      return Result<HttpIncomingBody *>::err(154);
    }
    auto borrow = Borrow<HttpIncomingResponse>(handle_state_.get());
    incoming_body_t body;
    if (!wasi_http_types_method_incoming_response_consume(borrow, &body)) {
      return Result<HttpIncomingBody *>::err(154);
    }
    body_ = new HttpIncomingBody(std::unique_ptr<HandleState>(new IncomingBodyHandle(body)));
  }
  return Result<HttpIncomingBody *>::ok(body_);
}

HttpOutgoingResponse::HttpOutgoingResponse(std::unique_ptr<HandleState> state) {
  this->handle_state_ = std::move(state);
}

HttpOutgoingResponse *HttpOutgoingResponse::make(const uint16_t status,
                                                 unique_ptr<HttpHeaders> headers) {
  auto owned_headers = WASIHandle<HttpHeaders>::cast(headers->handle_state_.get())->take();
  auto handle = wasi_http_types_constructor_outgoing_response(owned_headers);

  auto *state = new WASIHandle<HttpOutgoingResponse>(handle);
  auto *resp = new HttpOutgoingResponse(std::unique_ptr<HandleState>(state));

  // Set the status
  if (status != 200) {
    // The DOM implementation is expected to have validated the status code already.
    MOZ_RELEASE_ASSERT(
        wasi_http_types_method_outgoing_response_set_status_code(state->borrow(), status));
  }

  resp->status_ = status;
  return resp;
}

Result<HttpHeadersReadOnly *> HttpOutgoingResponse::headers() {
  if (!headers_) {
    if (!valid()) {
      return Result<HttpHeadersReadOnly *>::err(154);
    }
    auto borrow = Borrow<HttpOutgoingResponse>(handle_state_.get());
    auto res = wasi_http_types_method_outgoing_response_headers(borrow);
    auto state = new WASIHandle<HttpHeaders>(res);
    headers_ = new HttpHeadersReadOnly(std::unique_ptr<HandleState>(state));
  }

  return Result<HttpHeadersReadOnly *>::ok(headers_);
}

Result<HttpOutgoingBody *> HttpOutgoingResponse::body() {
  typedef Result<HttpOutgoingBody *> Res;
  if (!this->body_) {
    auto borrow = Borrow<HttpOutgoingResponse>(handle_state_.get());
    outgoing_body_t body;
    if (!wasi_http_types_method_outgoing_response_body(borrow, &body)) {
      return Res::err(154);
    }
    body_ = new HttpOutgoingBody(std::unique_ptr<HandleState>(new OutgoingBodyHandle(body)));
  }
  return Res::ok(this->body_);
}
Result<uint16_t> HttpOutgoingResponse::status() { return Result<uint16_t>::ok(status_); }

HttpIncomingRequest::HttpIncomingRequest(std::unique_ptr<HandleState> state) {
  handle_state_ = std::move(state);
}

Result<string_view> HttpIncomingRequest::method() {
  if (method_.empty()) {
    if (!valid()) {
      return Result<string_view>::err(154);
    }
  }
  auto borrow = Borrow<HttpIncomingRequest>(handle_state_.get());
  wasi_http_types_method_t method;
  wasi_http_types_method_incoming_request_method(borrow, &method);
  if (method.tag != WASI_HTTP_TYPES_METHOD_OTHER) {
    method_ = std::string(http_method_names[method.tag], strlen(http_method_names[method.tag]));
  } else {
    method_ = std::string(reinterpret_cast<char *>(method.val.other.ptr), method.val.other.len);
    bindings_string_free(&method.val.other);
  }
  return Result<string_view>::ok(method_);
}

Result<HttpHeadersReadOnly *> HttpIncomingRequest::headers() {
  if (!headers_) {
    if (!valid()) {
      return Result<HttpHeadersReadOnly *>::err(154);
    }
    auto borrow = Borrow<HttpIncomingRequest>(handle_state_.get());
    auto res = wasi_http_types_method_incoming_request_headers(borrow);
    auto state = new WASIHandle<HttpHeaders>(res);
    headers_ = new HttpHeadersReadOnly(std::unique_ptr<HandleState>(state));
  }

  return Result<HttpHeadersReadOnly *>::ok(headers_);
}

Result<HttpIncomingBody *> HttpIncomingRequest::body() {
  if (!body_) {
    if (!valid()) {
      return Result<HttpIncomingBody *>::err(154);
    }
    auto borrow = Borrow<HttpIncomingRequest>(handle_state_.get());
    incoming_body_t body;
    if (!wasi_http_types_method_incoming_request_consume(borrow, &body)) {
      return Result<HttpIncomingBody *>::err(154);
    }
    body_ = new HttpIncomingBody(std::unique_ptr<HandleState>(new IncomingBodyHandle(body)));
  }
  return Result<HttpIncomingBody *>::ok(body_);
}

namespace filesystem {

namespace types {

Descriptor::Descriptor(std::unique_ptr<HandleState> state) { handle_state_ = std::move(state); }

Result<Descriptor *> Descriptor::open_at(uint64_t path_flags, string_view path, uint64_t open_flags,
                                         uint64_t flags) {
  wasi_filesystem_types_own_descriptor_t ret{};
  wasi_filesystem_types_error_code_t err{};
  auto borrow = Borrow<Descriptor>(handle_state_.get());
  if (wasi_filesystem_types_method_descriptor_open_at(
          borrow, path_flags, &string_view_to_world_string(path), open_flags, flags, &ret, &err)) {
    auto state = new WASIHandle<Descriptor>(ret);
    return Result<Descriptor *>::ok(new Descriptor(std::unique_ptr<HandleState>(state)));
  } else {
    // TODO: handle `err` (dump it? idk)
    // TODO: idk what this magical `154` is but I imagine it doesn't apply to
    // filesystem ops, since I just took it from the Http stuff, but I'm looking
    // at other stuff first.
    return Result<Descriptor *>::err(154);
  }
}

Result<Descriptor::ReadResult> Descriptor::read_sync(size_t offset, uint64_t chunk_size) {
  typedef Result<ReadResult> Res;

  bindings_list_u8_t ret{};
  wasi_io_streams_stream_error_t err{};
  auto body_handle = IncomingDescriptorHandle::cast(handle_state_.get());
  auto borrow = Borrow<InputStream>(body_handle->stream_handle_);
  bool success = wasi_io_streams_method_input_stream_read(borrow, chunk_size, &ret, &err);
  if (!success) {
    if (err.tag == WASI_IO_STREAMS_STREAM_ERROR_CLOSED) {
      return Res::ok(ReadResult(true, nullptr, 0));
    }
    dump_io_error(err);
    return Res::err(154);
  }
  return Res::ok(ReadResult(false, unique_ptr<uint8_t[]>(ret.ptr), ret.len));
}

namespace impl {

// TODO(@zkat): Add appropriate stuff to the .h
// TODO(@zkat): optional -> Result where failures are actually errors.

using std::string;
// All lazily initialized to avoid startup cost.
static bool cwd_initialized{false};
static optional<const string> cwd_str{nullopt};
static optional<Descriptor *> cwd_fd{nullopt};
// You might think you want a fancy tree here but you don't. This is only ever
// going to have like 2-3 items. A vector is probably already overkill.
// Benchmark later if this seems suspect.
static optional<vector<tuple<Descriptor *, string>> *> preopens{nullopt};

optional<Descriptor *> get_init_cwd_fd() {
  auto maybe_init_cwd = host_api::environment_initial_cwd();
  if (maybe_init_cwd.has_value()) {
  } else {
    return std::nullopt;
  }
}

optional<const Descriptor *> get_cwd() {
  if (!cwd_initialized) {
    cwd_str = host_api::environment_initial_cwd();
    if (cwd_str.has_value()) {
      string_view cwd_val = cwd_str.value();
      auto base = relative_to(cwd_val, false);
      if (base.has_value()) {
        auto &[fd, base_path] = base.value();
        // TODO(@zkat): uhhh... flags. Those are important. lol
        auto res = fd->open_at(0, cwd_val.substr(base_path.length()), 0, 0);
        // TODO(@zkat): I think this'll bubble up as an error in the right place
        // just fine? Might change this function to return a Result later if I
        // want it to give more explicit errors.
        if (res.is_err())
          return nullopt;
        cwd_fd = res.unwrap();
      }
    }
    cwd_initialized = true;
  }
  return cwd_fd;
}

optional<tuple<Descriptor *, const std::string_view>> relative_to(string_view const &path) {
  return relative_to(path, cwd_initialized);
}

optional<tuple<Descriptor *, const std::string_view>> relative_to(string_view const &path,
                                                                  bool search_relative_paths) {
  // NB(@zkat): I'm making a HUGE assumption here, which is that preopened paths
  // are always returned as absolute paths. It has not been See if `path` is an
  // absolute path prefixed by any of the preopened directories. The reference
  // I'm looking at literally just says `Return the set of preopened
  // directories, and their path.` 🙃
  // I'm betting on absolute paths just like I bet on JS.
  auto base = find_base(path);

  if (base.has_value()) {
    auto &[fd, fd_path] = base.value();
    return tuple(fd, std::filesystem::relative(path, fd_path).string());
  }

  // If we haven't found one, it might be relative. So we go ahead and try that
  // next, using our cwd, if any.

  // NB(@zkat): This is mainly meant for `get_cwd()`, to base case recursion.
  if (!search_relative_paths)
    return nullopt;

  // If we have a relative path, let's go ahead and check it against cwd.
  if (
      // NB(@zkat): C++ treats `/`-rooted paths as relative on Windows. I would
      // not expect this to be a problem, but I'm not sure what it's going to do
      // when running in wasmtime/StarlingMonkey on Windows, so I'm just gonna
      // hard-code the one correct answer (because `WASI` explicitly only accepts
      // `/`. This is safe.)
      !path.starts_with('/') && cwd_str.has_value()) {
    string_view cwd = cwd_str.value();
    std::filesystem::path p(cwd);
    p /= path;
    string new_path = p.string();
    auto base = find_base(new_path);
    if (base.has_value()) {
      auto &[fd, fd_path] = base.value();
      return tuple(fd, std::filesystem::relative(new_path, fd_path).string());
    }
  }

  return nullopt;
}

// Helper. Assumes you're calling it through `relative_to`.
optional<tuple<Descriptor *, const string_view>> find_base(string_view const &path) {
  if (!preopens.has_value()) {
    // Only initialize if we're actually going to try and open something.
    preopens = preopens::get_directories();
  }
  // NB(@zkat): Uhhh... I'm not _entirely_ sure the `*` here is appropriate but YOLO for
  // now. Still wrapping my head around how pointer stuff is done in this
  // project/wasi/etc.
  for (auto &[fd, base_path] : *preopens.value()) {
    // NB(@zkat): I am assuming, for right now, that the
    // `preopens_get_directories()` paths are all absolute, since... I'm not
    // sure where to start if I had to hand-resolve them.
    if (path.starts_with(base_path)) {
      return tuple(fd, string_view(base_path));
    }
  }
  return nullopt;
}

} // namespace impl
} // namespace types

Result<types::Descriptor *> open(string_view const &path) {
  auto res = types::impl::relative_to(path);
  if (!res.has_value())
    // TODO(@zkat): EACCES probably. I gotta do better about this.
    return host_api::Result<types::Descriptor *>::err(154);

  auto &[fd, rel] = res.value();
  // TODO(@zkat): flags
  auto res = fd->open_at(0, rel, 0, 0);
  return host_api::Result<types::Descriptor *>::ok(res.value());
}

namespace preopens {

vector<tuple<types::Descriptor *, std::string>> *get_directories() {
  wasi_filesystem_preopens_list_tuple2_own_descriptor_string_t ret{};
  wasi_filesystem_preopens_get_directories(&ret);
  // TODO(@zkat): uhhhh... construct stuff, I guess?
}
} // namespace preopens

} // namespace filesystem
optional<std::string> environment_initial_cwd() {
  bindings_string_t ret{};
  wasi_cli_environment_initial_cwd(&ret);
  return std::string(reinterpret_cast<char *>(ret.ptr, ret.len));
}

} // namespace host_api

static host_api::HttpIncomingRequest::RequestHandler REQUEST_HANDLER = nullptr;
static exports_wasi_http_response_outparam RESPONSE_OUT;

void host_api::HttpIncomingRequest::set_handler(RequestHandler handler) {
  MOZ_ASSERT(!REQUEST_HANDLER);
  REQUEST_HANDLER = handler;
}

host_api::Result<host_api::Void> host_api::HttpOutgoingResponse::send() {
  wasi_http_types_result_own_outgoing_response_error_code_t result;

  auto own = WASIHandle<HttpOutgoingResponse>::cast(this->handle_state_.get())->take();

  result.is_err = false;
  result.val.ok = own;

  wasi_http_types_static_response_outparam_set(RESPONSE_OUT, &result);

  return {};
}

extern "C" bool init_from_environment();

void exports_wasi_http_incoming_handler(exports_wasi_http_incoming_request request_handle,
                                        exports_wasi_http_response_outparam response_out) {
  // If StarlingMonkey hasn't been pre-initialized, no request handler will be installed yet.
  // The embedding must provide an implementation of the `init_from_environment()` hook and ensure
  // that it properly initializes the runtime and installs a request handler.
  if (!REQUEST_HANDLER) {
    init_from_environment();
  }
  MOZ_ASSERT(REQUEST_HANDLER);

  RESPONSE_OUT = response_out;
  auto state = new WASIHandle<host_api::HttpIncomingRequest>(request_handle);
  auto *request = new host_api::HttpIncomingRequest(std::unique_ptr<host_api::HandleState>(state));
  auto res = REQUEST_HANDLER(request);
  MOZ_RELEASE_ASSERT(res);
}
