#ifndef _SWIFT_DEBUG_H
#define _SWIFT_DEBUG_H

#define log_error(...) printk(KERN_ERR "SWIF-ERROR : " __VA_ARGS__)

#if 0

#define log_debug(...) printk(KERN_DEBUG "SWIF-DEBUG : " __VA_ARGS__)

#else

#define log_debug(...)

#endif

#endif
