/** @file
 *
 * Declarations that etwdump uses and that MinGW-w64's headers lack.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __ETW_COMPAT_H__
#define __ETW_COMPAT_H__

#include <windows.h>
#include <evntcons.h>
#include <tdh.h>

#ifdef __MINGW32__
/*
 * As of mingw-w64 14, tdh.h is the Windows Vista version. It doesn't have
 * TDHSTATUS, the _TDH_IN_TYPE and _TDH_OUT_TYPE enumerations, or
 * TdhFormatProperty, although libtdh.a exports TdhFormatProperty.
 * The values are from the Windows SDK's tdh.h.
 */
typedef ULONG TDHSTATUS;

#define TDH_INTYPE_UNICODESTRING 1
#define TDH_INTYPE_ANSISTRING    2
#define TDH_INTYPE_BINARY        14
#define TDH_OUTTYPE_IPV6         24

#ifdef __cplusplus
extern "C" {
#endif

TDHSTATUS __stdcall
TdhFormatProperty(
    PTRACE_EVENT_INFO EventInfo,
    PEVENT_MAP_INFO MapInfo,
    ULONG PointerSize,
    USHORT PropertyInType,
    USHORT PropertyOutType,
    USHORT PropertyLength,
    USHORT UserDataLength,
    PBYTE UserData,
    PULONG BufferSize,
    PWCHAR Buffer,
    PUSHORT UserDataConsumed
    );

#ifdef __cplusplus
}
#endif
#endif /* __MINGW32__ */

/* MinGW-w64's evntcons.h stops at EVENT_ENABLE_PROPERTY_STACK_TRACE. */
#ifndef EVENT_ENABLE_PROPERTY_PROCESS_START_KEY
#define EVENT_ENABLE_PROPERTY_PROCESS_START_KEY         0x00000080
#endif
#ifndef EVENT_ENABLE_PROPERTY_EVENT_KEY
#define EVENT_ENABLE_PROPERTY_EVENT_KEY                 0x00000100
#endif
#ifndef EVENT_ENABLE_PROPERTY_ENABLE_SILOS
#define EVENT_ENABLE_PROPERTY_ENABLE_SILOS              0x00000400
#endif
#ifndef EVENT_ENABLE_PROPERTY_SOURCE_CONTAINER_TRACKING
#define EVENT_ENABLE_PROPERTY_SOURCE_CONTAINER_TRACKING 0x00000800
#endif

#endif /* __ETW_COMPAT_H__ */
