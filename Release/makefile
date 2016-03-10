################################################################################
# Automatically-generated file. Do not edit!
################################################################################

SHELL = cmd.exe

CG_TOOL_ROOT := C:/TI/ccsv6/tools/compiler/ti-cgt-arm_5.2.5

GEN_OPTS__FLAG := 
GEN_CMDS__FLAG := 

ORDERED_OBJS += \
"./Adafruit_GFX.obj" \
"./Adafruit_OLED.obj" \
"./cJSON.obj" \
"./gpio_if.obj" \
"./main.obj" \
"./pinmux.obj" \
"./startup_ccs.obj" \
"./uart_if.obj" \
"../cc3200v1p32.cmd" \
$(GEN_CMDS__FLAG) \
-l"libc.a" \
-l"C:/ti/CC3200SDK_1.1.0/cc3200-sdk/example/ssl/ccs/../../../driverlib/ccs/Release/driverlib.a" \
-l"C:/ti/CC3200SDK_1.1.0/cc3200-sdk/example/ssl/ccs/../../../simplelink/ccs/NON_OS/simplelink.a" \

-include ../makefile.init

RM := DEL /F
RMDIR := RMDIR /S/Q

# All of the sources participating in the build are defined here
-include sources.mk
-include subdir_vars.mk
-include subdir_rules.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(S_DEPS)),)
-include $(S_DEPS)
endif
ifneq ($(strip $(S_UPPER_DEPS)),)
-include $(S_UPPER_DEPS)
endif
ifneq ($(strip $(S62_DEPS)),)
-include $(S62_DEPS)
endif
ifneq ($(strip $(C64_DEPS)),)
-include $(C64_DEPS)
endif
ifneq ($(strip $(ASM_DEPS)),)
-include $(ASM_DEPS)
endif
ifneq ($(strip $(CC_DEPS)),)
-include $(CC_DEPS)
endif
ifneq ($(strip $(S55_DEPS)),)
-include $(S55_DEPS)
endif
ifneq ($(strip $(C67_DEPS)),)
-include $(C67_DEPS)
endif
ifneq ($(strip $(CLA_DEPS)),)
-include $(CLA_DEPS)
endif
ifneq ($(strip $(C??_DEPS)),)
-include $(C??_DEPS)
endif
ifneq ($(strip $(CPP_DEPS)),)
-include $(CPP_DEPS)
endif
ifneq ($(strip $(S??_DEPS)),)
-include $(S??_DEPS)
endif
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
ifneq ($(strip $(C62_DEPS)),)
-include $(C62_DEPS)
endif
ifneq ($(strip $(CXX_DEPS)),)
-include $(CXX_DEPS)
endif
ifneq ($(strip $(C++_DEPS)),)
-include $(C++_DEPS)
endif
ifneq ($(strip $(ASM_UPPER_DEPS)),)
-include $(ASM_UPPER_DEPS)
endif
ifneq ($(strip $(K_DEPS)),)
-include $(K_DEPS)
endif
ifneq ($(strip $(C43_DEPS)),)
-include $(C43_DEPS)
endif
ifneq ($(strip $(INO_DEPS)),)
-include $(INO_DEPS)
endif
ifneq ($(strip $(S67_DEPS)),)
-include $(S67_DEPS)
endif
ifneq ($(strip $(SA_DEPS)),)
-include $(SA_DEPS)
endif
ifneq ($(strip $(S43_DEPS)),)
-include $(S43_DEPS)
endif
ifneq ($(strip $(OPT_DEPS)),)
-include $(OPT_DEPS)
endif
ifneq ($(strip $(PDE_DEPS)),)
-include $(PDE_DEPS)
endif
ifneq ($(strip $(S64_DEPS)),)
-include $(S64_DEPS)
endif
ifneq ($(strip $(C_UPPER_DEPS)),)
-include $(C_UPPER_DEPS)
endif
ifneq ($(strip $(C55_DEPS)),)
-include $(C55_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 
EXE_OUTPUTS += \
lab5\ 3rd.out \

EXE_OUTPUTS__QUOTED += \
"lab5 3rd.out" \

BIN_OUTPUTS += \
lab5\ 3rd.bin \

BIN_OUTPUTS__QUOTED += \
"lab5 3rd.bin" \


# All Target
all: lab5\ 3rd.out

# Tool invocations
lab5\ 3rd.out: $(OBJS) $(CMD_SRCS) $(GEN_CMDS)
	@echo 'Building target: $@'
	@echo 'Invoking: ARM Linker'
	"C:/TI/ccsv6/tools/compiler/ti-cgt-arm_5.2.5/bin/armcl" -mv7M4 --code_state=16 --float_support=vfplib --abi=eabi -me -O2 --opt_for_speed=2 -g --gcc --define=ccs --define=cc3200 --diag_warning=225 --display_error_number --diag_wrap=off --printf_support=full -z -m"lab5 3rd.map" --heap_size=0x00008000 --stack_size=0x00001000 -i"C:/TI/ccsv6/tools/compiler/ti-cgt-arm_5.2.5/lib" -i"C:/TI/ccsv6/tools/compiler/ti-cgt-arm_5.2.5/include" --reread_libs --warn_sections --diag_wrap=off --display_error_number --xml_link_info="lab5 3rd_linkInfo.xml" --rom_model -o "lab5 3rd.out" $(ORDERED_OBJS)
	@echo 'Finished building target: $@'
	@echo ' '
	@$(MAKE) --no-print-directory post-build

lab5\ 3rd.bin: $(EXE_OUTPUTS)
	@echo 'Invoking: ARM Hex Utility'
	"C:/TI/ccsv6/tools/compiler/ti-cgt-arm_5.2.5/bin/armhex"  -o "lab5 3rd.bin" $(EXE_OUTPUTS__QUOTED)
	@echo 'Finished building: $@'
	@echo ' '
	@$(MAKE) --no-print-directory post-build

# Other Targets
clean:
	-$(RM) $(EXE_OUTPUTS__QUOTED)$(BIN_OUTPUTS__QUOTED)
	-$(RM) "Adafruit_GFX.pp" "Adafruit_OLED.pp" "cJSON.pp" "gpio_if.pp" "main.pp" "pinmux.pp" "startup_ccs.pp" "uart_if.pp" 
	-$(RM) "Adafruit_GFX.obj" "Adafruit_OLED.obj" "cJSON.obj" "gpio_if.obj" "main.obj" "pinmux.obj" "startup_ccs.obj" "uart_if.obj" 
	-@echo 'Finished clean'
	-@echo ' '

post-build:
	-@echo 'Bin Generation'
	-"C:/TI/ccsv6/utils/tiobj2bin/tiobj2bin" "lab5 3rd.out" "lab5 3rd.bin" "C:/TI/ccsv6/tools/compiler/ti-cgt-arm_5.2.5/bin/armofd" "C:/TI/ccsv6/tools/compiler/ti-cgt-arm_5.2.5/bin/armhex" "C:/TI/ccsv6/utils/tiobj2bin/mkhex4bin"
	-@echo ' '

.PHONY: all clean dependents
.SECONDARY: post-build

-include ../makefile.targets

