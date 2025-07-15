/**
 * SwizzleMeTimbers
 *
 * To solve this challenge is sufficient to change the return value 
 * of the function '$s16SwizzleMeTimbers4Q9V0C4_9zBSbyF' ( SwizzleMeTimbers.Q9V0._9zB() -> Swift.Bool )
 *
 * Flag: CTF{{Swizzle_mbers}}
 *
**/


const targetFunc = Process.getModuleByName("SwizzleMeTimbers.debug.dylib").getSymbolByName("$s16SwizzleMeTimbers4Q9V0C4_9zBSbyF");

Interceptor.attach(targetFunc, {onLeave(retval){ this.context.x0 = ptr(0x1); }});
