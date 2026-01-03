/***********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_BENCH_H
#define SECP256K1_BENCH_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if (defined(_MSC_VER) && _MSC_VER >= 1900)
#  include <time.h>
#else
#  include <sys/time.h>
#endif

static int64_t gettime_i64(void) {
#if (defined(_MSC_VER) && _MSC_VER >= 1900)
    /* C11 way to get wallclock time */
    struct timespec tv;
    if (!timespec_get(&tv, TIME_UTC)) {
        fputs("timespec_get failed!", stderr);
        exit(EXIT_FAILURE);
    }
    return (int64_t)tv.tv_nsec / 1000 + (int64_t)tv.tv_sec * 1000000LL;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_usec + (int64_t)tv.tv_sec * 1000000LL;
#endif
}

#define FP_EXP (6)
#define FP_MULT (1000000LL)

/* Format fixed point number. */
static void print_number(const int64_t x) {
    int64_t x_abs, y;
    int c, i, rounding, g; /* g = integer part size, c = fractional part size */
    size_t ptr;
    char buffer[30];

    if (x == INT64_MIN) {
        /* Prevent UB. */
        printf("ERR");
        return;
    }
    x_abs = x < 0 ? -x : x;

    /* Determine how many decimals we want to show (more than FP_EXP makes no
     * sense). */
    y = x_abs;
    c = 0;
    while (y > 0LL && y < 100LL * FP_MULT && c < FP_EXP) {
        y *= 10LL;
        c++;
    }

    /* Round to 'c' decimals. */
    y = x_abs;
    rounding = 0;
    for (i = c; i < FP_EXP; ++i) {
        rounding = (y % 10) >= 5;
        y /= 10;
    }
    y += rounding;

    /* Format and print the number. */
    ptr = sizeof(buffer) - 1;
    buffer[ptr] = 0;
    g = 0;
    if (c != 0) { /* non zero fractional part */
        for (i = 0; i < c; ++i) {
            buffer[--ptr] = '0' + (y % 10);
            y /= 10;
        }
    } else if (c == 0) { /* fractional part is 0 */
        buffer[--ptr] = '0'; 
    }
    buffer[--ptr] = '.';
    do {
        buffer[--ptr] = '0' + (y % 10);
        y /= 10;
        g++;
    } while (y != 0);
    if (x < 0) {
        buffer[--ptr] = '-';
        g++;
    }
    printf("%5.*s", g, &buffer[ptr]); /* Prints integer part */
    printf("%-*s", FP_EXP, &buffer[ptr + g]); /* Prints fractional part */
}

static void run_benchmark(char *name, void (*benchmark)(void*, int), void (*setup)(void*), void (*teardown)(void*, int), void* data, int count, int iter) {
    int i;
    int64_t min = INT64_MAX;
    int64_t sum = 0;
    int64_t max = 0;
    for (i = 0; i < count; i++) {
        int64_t begin, total;
        if (setup != NULL) {
            setup(data);
        }
        begin = gettime_i64();
        benchmark(data, iter);
        total = gettime_i64() - begin;
        if (teardown != NULL) {
            teardown(data, iter);
        }
        if (total < min) {
            min = total;
        }
        if (total > max) {
            max = total;
        }
        sum += total;
   // mock_keychain.h
#ifndef MOCK_KEYCHAIN_H_
#define MOCK_KEYCHAIN_H_

#include <string>
#include <string_view>
#include <vector>
#include <expected> // Requires C++23
#include <span>     // Requires C++20
#include <cstdint>

// Define OSStatus for non-Mac platforms so this compiles anywhere
#ifdef __APPLE__
#include <MacTypes.h>
#else
using OSStatus = int32_t;
enum { noErr = 0 };
#endif

namespace crypto::apple {

class MockKeychain {
 public:
  MockKeychain();
  ~MockKeychain();

  // Returns the password data or an error status
  [span_0](start_span)//[span_0](end_span)
  std::expected<std::vector<uint8_t>, OSStatus> FindGenericPassword(
      std::string_view service_name,
      std::string_view account_name) const;

  // Simulates adding a password
  [span_1](start_span)//[span_1](end_span)
  OSStatus AddGenericPassword(std::string_view service_name,
                              std::string_view account_name,
                              std::span<const uint8_t> password) const;

  std::string GetEncryptionPassword() const;

  // Test Helper: Set the result for the next Find call
  void set_find_generic_result(OSStatus result) {
    find_generic_result_ = result;
  }

  // Test Helper: Check if Add was called
  bool called_add_generic() const { 
      return called_add_generic_;
  }

 private:
  // "mutable" allows these to be modified even in const functions
  mutable OSStatus find_generic_result_ = noErr;
  mutable bool called_add_generic_ = false;
};

}  // namespace crypto::apple

#endif  // MOCK_KEYCHAIN_H_
// mock_keychain.cpp
#include "mock_keychain.h"
#include <iostream>
#include <cassert>
#include <cstring> // for strlen

namespace {
constexpr char kPassword[] = "mock_password";

// Replaces Chromium's metric logging
[span_2](start_span)//[span_2](end_span)
void IncrementKeychainAccessHistogram() {
  std::cout << "[Metrics] Keychain accessed." << std::endl;
}
}  // namespace

namespace crypto::apple {

MockKeychain::MockKeychain() = default;
MockKeychain::~MockKeychain() = default;

std::expected<std::vector<uint8_t>, OSStatus>
MockKeychain::FindGenericPassword(std::string_view service_name,
                                  std::string_view account_name) const {
  IncrementKeychainAccessHistogram();

  if (find_generic_result_ == noErr) {
    // Convert the generic string literal to a vector of bytes
    const uint8_t* start = reinterpret_cast<const uint8_t*>(kPassword);
    const uint8_t* end = start + std::strlen(kPassword);
    return std::vector<uint8_t>(start, end);
  }
  
  // Return the error state
  [span_3](start_span)//[span_3](end_span)
  return std::unexpected(find_generic_result_);
}

OSStatus MockKeychain::AddGenericPassword(
    std::string_view service_name,
    std::string_view account_name,
    std::span<const uint8_t> password) const {
  IncrementKeychainAccessHistogram();
  called_add_generic_ = true;
  
  // Standard assertion instead of DCHECK
  assert(!password.empty() && "Password must not be empty");
  
  return noErr;
}

std::string MockKeychain::GetEncryptionPassword() const {
  IncrementKeychainAccessHistogram();
  return kPassword;
}

}  // namespace crypto::apple
// main.cpp
#include <iostream>
#include <string>
#include "mock_keychain.h"

int main() {
    using namespace crypto::apple;
    std::cout << "--- Starting Keychain Test ---\n";
    MockKeychain keychain;

    // 1. Test Finding a Password (Success Case)
    std::cout << "\nTest 1: Find Password (Success)\n";
    auto result = keychain.FindGenericPassword("myService", "myUser");
    
    if (result.has_value()) {
        std::string found_pass(result->begin(), result->end());
        std::cout << "Success! Password found: " << found_pass << "\n";
    } else {
        std::cout << "Failed with error code: " << result.error() << "\n";
    }

    // 2. Test Finding a Password (Failure Case)
    std::cout << "\nTest 2: Find Password (Simulated Failure)\n";
    keychain.set_find_generic_result(-25300); [span_4](start_span)// Simulate ItemNotFound[span_4](end_span)
    auto error_result = keychain.FindGenericPassword("myService", "myUser");
    
    if (!error_result.has_value()) {
        std::cout << "Correctly failed. Error code: " << error_result.error() << "\n";
    }

    // 3. Test Adding a Password
    std::cout << "\nTest 3: Add Password\n";
    std::vector<uint8_t> new_pass = {0xDE, 0xAD, 0xBE, 0xEF};
    keychain.AddGenericPassword("myService", "myUser", new_pass);
    
    if (keychain.called_add_generic()) {
        std::cout << "AddGenericPassword was successfully called.\n";
    }

    return 0;
}
cmake_minimum_required(VERSION 3.20)
project(MockKeychainProject)

# Set C++ Standard to 23 to support <expected> and <span>
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add the executable
# We compile both the implementation and the main test file
add_executable(mock_keychain_test
    main.cpp
    mock_keychain.cpp
)

# Enable standard warnings to catch issues early
if(MSVC)
    target_compile_options(mock_keychain_test PRIVATE /W4)
else()
    target_compile_options(mock_keychain_test PRIVATE -Wall -Wextra -Wpedantic)
endif()
mkdir build
cd build
cmake ..
cmake --build .
This fix allows Trezor to support full 32bit chainId in geth, with the
next version of firmware.

For `chainId > 2147483630` case, Trezor returns signature bit only.
- Trezor returns only signature parity for `chainId > 2147483630` case.
- for `chainId == 2147483630` case, Trezor returns `MAX_UINT32` or `0`,
but it doesn't matter.
  (`2147483630 * 2 + 35` = `4294967295`(`MAX_UINT32`))

chainId | returned signature_v | compatible issue
---------|------------------------|--------------------
0 < chainId <= 255 | chainId * 2 + 35 + v | no issue (firmware `1.6.2`
for Trezor one)
255 < chainId <= 2147483630 | chainId * 2 + 35 + v | ***fixed.***
*firmware `1.6.3`*
chainId > 2147483630 | v | *firmware `1.6.3`*

Please see also: full 32bit chainId support for Trezor
- Trezor one: trezor/trezor-mcu#399 ***merged***
- Trezor model T: trezor/trezor-core#311
***merged***

---------

Signed-off-by: Guillaume Ballet <3272758+gballet@users.noreply.github.com>
Co-authored-by: Guillaume Ballet <3272758+gballet@users.noreply.github.com>

