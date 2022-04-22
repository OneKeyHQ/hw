from trezor import utils

import lvgl as lv  # type: ignore[Import "lvgl" could not be resolved]

dispp = lv.disp_get_default()
theme = lv.theme_default_init(
    dispp,
    lv.palette_main(lv.PALETTE.BLUE),
    lv.palette_main(lv.PALETTE.RED),
    True,
    lv.font_default(),
)
dispp.set_theme(theme)

if utils.EMULATOR:
    font_PJSBOLD36 = lv.font_load("A:/res/PlusJakartaSans-Bold-36.bin")
    font_PJSBOLD32 = lv.font_load("A:/res/PlusJakartaSans-Bold-32.bin")
    font_PJSBOLD24 = lv.font_load("A:/res/PlusJakartaSans-Bold-24.bin")
    font_PJSBOLD20 = lv.font_load("A:/res/PlusJakartaSans-Bold-20.bin")
    font_PJSMID28 = lv.font_load("A:/res/PlusJakartaSans-Medium-28.bin")
    font_PJSMID24 = lv.font_load("A:/res/PlusJakartaSans-Medium-24.bin")
    font_PJSMID20 = lv.font_load("A:/res/PlusJakartaSans-Medium-20.bin")
    font_PJSREG24 = lv.font_load("A:/res/PlusJakartaSans-Regular-24.bin")
    font_MONO32 = lv.font_load("A:/res/JetBrainsMono-Bold-32.bin")
    font_MONO28 = lv.font_load("A:/res/JetBrainsMono-Medium-28.bin")
    font_MONO24 = lv.font_load("A:/res/JetBrainsMono-Medium-24.bin")

else:
    font_PJSBOLD36 = lv.font_pljs_bold_36
    font_PJSBOLD32 = lv.font_pljs_bold_32
    font_PJSBOLD24 = lv.font_pljs_bold_24
    font_PJSBOLD20 = lv.font_pljs_bold_20
    font_PJSMID28 = lv.font_pljs_medium_28
    font_PJSMID24 = lv.font_pljs_medium_24
    font_PJSMID20 = lv.font_pljs_medium_20
    font_PJSREG24 = lv.font_pljs_regular_24
    font_MONO32 = lv.font_jbm_bold_32
    font_MONO28 = lv.font_jbm_medium_28
    font_MONO24 = lv.font_jbm_medium_24
