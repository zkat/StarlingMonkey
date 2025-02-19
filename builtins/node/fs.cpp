#include "fs.h"

#include "builtin.h"
#include "encode.h"
#include "host_api.h"

namespace builtins::node::fs {

bool readFileSync(JSContext *cx, unsigned argc, Value *vp) {
  CallArgs args = CallArgsFromVp(argc, vp);
  if (!args.requireAtLeast(cx, "fetch", 1))
    return false;
  auto path = args.get(0);
  auto maybe_fd = host_api::filesystem::open_at(0, core::encode(cx, path), 0, 0);
  if (maybe_fd.is_err())
    // TODO(@zkat): error
    return false;

  auto fd = maybe_fd.unwrap();
  while (true) {
    auto maybe_res = fd->read_sync(0, 1024);
    if (maybe_res.is_err())
      // TODO(@zkat): error
      return false;
    auto &res = maybe_res.unwrap();
    if (!res.done)
      continue;
    auto &bytes = res.bytes;

    // TODO(@zkat): NO. THIS IS THE WRONG THING. The buffer obvs need to be
    // checked for proper utf-8 but I need to hunt down all the "proper"
    // shenanigans around doing this that have already been established. I'm
    // PURELY doing this reinterpret out of getting something working first.
    RootedString str(cx,
                     JS_NewStringCopyN(cx, reinterpret_cast<char *>(bytes.ptr.get()), bytes.len));
    // At this point `str` has taken full ownership of the bytes' data.
    std::ignore = bytes.ptr.release();
    if (!str) {
      // TODO(@zkat): error handling
      return false;
    }
    args.rval().setString(str);
    return true;
  }
}

bool install(api::Engine *engine) {
  JSContext *cx = engine->cx();
  JS::RootedObject node_fs(cx, JS_NewPlainObject(cx));
  if (!JS_DefineFunction(cx, node_fs, "readFileSync", readFileSync, 2, JSPROP_ENUMERATE))
    return false;

  JS::RootedValue result(cx);
  result.setObject(*node_fs);
  return engine->define_builtin_module("node:fs", result);
}

} // namespace builtins::node::fs
