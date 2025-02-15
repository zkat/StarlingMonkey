#include "fs.h"

#include "builtin.h"
#include "host_api.h"

namespace builtins::node::fs {

bool readFileSync(JSContext *cx, unsigned argc, Value *vp) {}

bool install(api::Engine *engine) {
  JSContext *cx = engine->cx();
  JS::RootedValue node_fs(cx, JS_NewPlainObject(cx));
  const JSFunctionSpec exports[] = {
      JS_FN("readFileSync", readFileSync, 2, JSPROP_ENUMERATE),
      JS_FS_END,
  };

  engine->define_builtin_module("node:fs", node_fs);
}

} // namespace builtins::node::fs
