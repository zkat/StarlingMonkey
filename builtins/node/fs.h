#ifndef BUILTINS_NODE_FS_H
#define BUILTINS_NODE_FS_H

#include "builtin.h"
#include "extension-api.h"

namespace builtins::node::fs {

// Actually, will set up the module.
bool install(api::Engine *engine);

/**
 * node:fs readFileSync
 */
bool readFileSync(JSContext *cx, unsigned argc, Value *vp);

}

#endif
