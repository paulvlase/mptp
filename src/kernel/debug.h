#ifndef _MPTP_DEBUG_H
#define _MPTP_DEBUG_H

#define log_error(...) printk(KERN_ERR "MPTP-ERROR : " __VA_ARGS__)

#if 0

#define log_debug(...) printk(KERN_DEBUG "MPTP-DEBUG : " __VA_ARGS__)

#else

#define log_debug(...)

#endif

#endif
