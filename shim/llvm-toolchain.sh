#!/usr/bin/env bash
# Sourced by PE build scripts. Ubuntu ships clang without a clang-cl alias.
exl_select_cl_driver() {
    if command -v clang-cl >/dev/null 2>&1; then
        EXITLAG_CL_DRIVER=(clang-cl)
    elif command -v clang >/dev/null 2>&1; then
        EXITLAG_CL_DRIVER=(clang --driver-mode=cl)
    else
        echo 'PE build requires clang-cl or clang with --driver-mode=cl' >&2
        return 1
    fi
}
exl_select_cl_driver
