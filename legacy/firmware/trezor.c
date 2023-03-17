/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "trezor.h"
#include "bitmaps.h"
#include "bl_check.h"
#include "buttons.h"
#include "common.h"
#include "compiler_traits.h"
#include "config.h"
#include "gettext.h"
#include "layout.h"
#include "layout2.h"
#include "memzero.h"
#include "oled.h"
#include "protect.h"
#include "rng.h"
#include "setup.h"
#include "timer.h"
#include "usb.h"
#include "util.h"
#if !EMULATOR
#include <libopencm3/stm32/desig.h>
#include "ble.h"
#include "otp.h"
#include "sys.h"
#endif
#ifdef USE_SECP256K1_ZKP
#include "zkp_context.h"
#endif

#ifdef USE_SECP256K1_ZKP
void secp256k1_default_illegal_callback_fn(const char *str, void *data) {
  (void)data;
  __fatal_error(NULL, str, __FILE__, __LINE__, __func__);
  return;
}

void secp256k1_default_error_callback_fn(const char *str, void *data) {
  (void)data;
  __fatal_error(NULL, str, __FILE__, __LINE__, __func__);
  return;
}
#endif

/* Screen timeout */
uint32_t system_millis_lock_start = 0;

void check_lock_screen(void) {
  buttonUpdate();

  // wake from screensaver on any button
  if (layoutLast == layoutScreensaver && (button.NoUp || button.YesUp)) {
    layoutHome();
    return;
  }

  // button held for long enough (2 seconds)
  if (layoutLast == layoutHome && button.NoDown >= 285000 * 2) {
    layoutDialogAdapter(&bmp_icon_question, _("Cancel"), _("Lock Device"), NULL,
                        _("Do you really want to"), _("lock your Trezor?"),
                        NULL, NULL, NULL, NULL);

    // wait until NoButton is released
    usbTiny(1);
    do {
      usbSleep(5);
      buttonUpdate();
    } while (!button.NoUp);

    // wait for confirmation/cancellation of the dialog
    do {
      usbSleep(5);
      buttonUpdate();
    } while (!button.YesUp && !button.NoUp);
    usbTiny(0);

    if (button.YesUp) {
      // lock the screen
      config_lockDevice();
      layoutScreensaver();
    } else {
      // resume homescreen
      layoutHome();
    }
  }

  // if homescreen is shown for too long
  if (layoutLast == layoutHome) {
    if ((timer_ms() - system_millis_lock_start) >=
        config_getAutoLockDelayMs()) {
      // lock the screen
      config_lockDevice();
      layoutScreensaver();
    }
  }
}

static void collect_hw_entropy(bool privileged) {
#if EMULATOR
  (void)privileged;
  memzero(HW_ENTROPY_DATA, HW_ENTROPY_LEN);
#else
  if (privileged) {
    desig_get_unique_id((uint32_t *)HW_ENTROPY_DATA);
    // set entropy in the OTP randomness block
    if (!flash_otp_is_locked(FLASH_OTP_BLOCK_RANDOMNESS)) {
      uint8_t entropy[FLASH_OTP_BLOCK_SIZE] = {0};
      random_buffer(entropy, FLASH_OTP_BLOCK_SIZE);
      flash_otp_write(FLASH_OTP_BLOCK_RANDOMNESS, 0, entropy,
                      FLASH_OTP_BLOCK_SIZE);
      flash_otp_lock(FLASH_OTP_BLOCK_RANDOMNESS);
    }
    // collect entropy from OTP randomness block
    flash_otp_read(FLASH_OTP_BLOCK_RANDOMNESS, 0, HW_ENTROPY_DATA + 12,
                   FLASH_OTP_BLOCK_SIZE);
  } else {
    // unprivileged mode => use fixed HW_ENTROPY
    memset(HW_ENTROPY_DATA, 0x3C, HW_ENTROPY_LEN);
  }
#endif
}

int main(void) {
#ifndef APPVER
  setup();
  __stack_chk_guard = random32();  // this supports compiler provided
                                   // unpredictable stack protection checks
  oledInit();
#else
  check_and_replace_bootloader(true);
  setupApp();
  ble_reset();
#if !EMULATOR
  register_timer("button", timer1s / 2, buttonsTimer);
  register_timer("charge_dis", timer1s, chargeDisTimer);
#endif
  __stack_chk_guard = random32();  // this supports compiler provided
                                   // unpredictable stack protection checks
#endif

  drbg_init();

  if (!is_mode_unprivileged()) {
    cpu_mode = PRIVILEGED;
    collect_hw_entropy(true);
    timer_init();
#ifdef APPVER
    // enable MPU (Memory Protection Unit)
    mpu_config_firmware();
#endif
  } else {
    cpu_mode = UNPRIVILEGED;
    collect_hw_entropy(false);
  }

#ifdef USE_SECP256K1_ZKP
  ensure(sectrue * (zkp_context_init() == 0), NULL);
#endif

#if DEBUG_LINK
  oledSetDebugLink(1);
#if !EMULATOR
  config_wipe();
#endif
#endif

  config_init();
  layoutHome();
  usbInit();

  for (;;) {
#if EMULATOR
    usbSleep(10);
    layoutHomeInfo();
#else
    usbPoll();
    layoutHomeInfo();
#endif
  }
  return 0;
}
