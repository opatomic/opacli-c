/*
 * Copyright Opatomic
 * Open sourced with ISC license. Refer to LICENSE for details.
 */

#if defined(_WIN32) && (defined(OPA_MBEDTLS) || defined(OPABIGINT_USE_MBED))

#include <limits.h>
#include <stddef.h>
#include <stdio.h>

// mbedtls links with vsnprintf_s which isn't available on win2k making the exe unusable. Instead,
// tell mingw/gcc to wrap the call to this function by using the link flags: -Wl,--wrap=vsnprintf_s
int __wrap_vsnprintf_s(char* buff, size_t buffLen, size_t count, const char* format, va_list ap);
__attribute__((used))
int __wrap_vsnprintf_s(char* buff, size_t buffLen, size_t count, const char* format, va_list ap) {
	int result = -1;
	if (count != _TRUNCATE && count != SIZE_MAX && count + 1 < buffLen) {
		buffLen = count + 1;
	}
	if (format != NULL && buffLen <= (size_t)INT_MAX) {
		result = vsnprintf(buff, buffLen, format, ap);
	}
	if (buff != NULL && buffLen > 0) {
		if (result < 0) {
			buff[0] = 0;
		} else if ((size_t)result >= buffLen) {
			buff[buffLen - 1] = 0;
		}
	}
	return result;
}

#else

// this is here to get rid of a warning for "an empty translation unit"
typedef int compilerWarningFix;

#endif
