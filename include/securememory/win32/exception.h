//
// This file is part of SecureMemory project <https://github.com/romanpauk/securememory>
//
// See LICENSE for license and copyright information
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#pragma once

#include <stdexcept>

namespace securememory::win32
{
    class exception : public std::exception
    {
    public:
        exception(const char* function, DWORD last_error = GetLastError())
            : last_error_(last_error)
            , function_(function)
        {}

        const char* what() const override { return function_; }
        DWORD get_last_error() const { return last_error_; }

    private:
        DWORD last_error_;
        const char* function_;
    };
}
