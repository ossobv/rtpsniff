#ifndef INCLUDED_ENDIAN_H
#define INCLUDED_ENDIAN_H
/* vim: set ts=8 sts=4 sw=4 tw=80 et: */
/*======================================================================
Copyright (C) 2004,2005,2009,2012,2013 Walter Doekes
  <walter+tthsum@wjd.nu>
This file is part of tthsum.

tthsum is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

tthsum is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with tthsum.  If not, see <http://www.gnu.org/licenses/>.
======================================================================*/

/**
 * Get byte order (endianness) for the host platform.
 */

/* Try to get BYTE_ORDER, BIG_ENDIAN and LITTLE_ENDIAN */
#if defined(__linux) || defined(__GLIBC__)
#   include <endian.h>
#   ifndef BIG_ENDIAN
#       define BIG_ENDIAN __BIG_ENDIAN
#   endif
#   ifndef LITTLE_ENDIAN
#       define LITTLE_ENDIAN __LITTLE_ENDIAN
#   endif
#   ifndef BYTE_ORDER
#       define BYTE_ORDER __BYTE_ORDER
#   endif
#elif defined(__FreeBSD__) || defined (__NetBSD__) || defined(__OpenBSD__)
    /* sys/types.h includes machine/endian.h */
#   include <sys/types.h>
#   define LITTLE_ENDIAN _LITTLE_ENDIAN
#   define BIG_ENDIAN _BIG_ENDIAN
#endif /* !__*BSD__ */

/* Test the values and try to set them by hand on failure */
#if LITTLE_ENDIAN == BIG_ENDIAN \
            || (BYTE_ORDER != LITTLE_ENDIAN && BYTE_ORDER != BIG_ENDIAN) \
            || !defined(BIG_ENDIAN) || !defined(LITTLE_ENDIAN)
#   undef BYTE_ORDER
#   undef BIG_ENDIAN
#   undef LITTLE_ENDIAN
#   define BIG_ENDIAN 4321
#   define LITTLE_ENDIAN 1234
#   if defined(__alpha) || defined(__i386__) || defined(__vax__) \
            || defined(_WIN32)
#       define BYTE_ORDER LITTLE_ENDIAN
#   else
#       define BYTE_ORDER BIG_ENDIAN
#   endif
#endif

#endif /* INCLUDED_ENDIAN_H */
