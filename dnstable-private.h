/*
 * Copyright (c) 2012, 2014 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DNSTABLE_PRIVATE_H
#define DNSTABLE_PRIVATE_H

#ifdef HAVE_ENDIAN_H
# include <endian.h>
#else
# ifdef HAVE_SYS_ENDIAN_H
#  include <sys/endian.h>
# endif
#endif

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mtbl.h>
#include <wdns.h>

/* This is a subset of the dnstable repo's dnstable-private.h with
 * just the content needed for dnstable_convert */

#define ENTRY_TYPE_RRSET			((uint8_t)0)
#define ENTRY_TYPE_RRSET_NAME_FWD		((uint8_t)1)
#define ENTRY_TYPE_RDATA			((uint8_t)2)
#define ENTRY_TYPE_RDATA_NAME_REV		((uint8_t)3)
#define ENTRY_TYPE_TIME_RANGE			((uint8_t)254)
#define ENTRY_TYPE_VERSION			((uint8_t)255)

#endif /* DNSTABLE_PRIVATE_H */
