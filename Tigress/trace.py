# Tracing Tigress instructions through the virtualized source code

opcodesStruct = """
  _1_fac__string$result_STA_0$value_LIT_0 = 123,
  _1_fac__constant_int$result_STA_0$value_LIT_0 = 132,
  _1_fac__formal$result_STA_0$value_LIT_0 = 3,
  _1_fac__returnVoid$ = 90,
  _1_fac__goto$label_LAB_0 = 91,
  _1_fac__convert_void_star2void_star$left_STA_0$result_STA_0 = 58,
  _1_fac__load_int$left_STA_0$result_STA_0 = 103,
  _1_fac__local$result_STA_0$value_LIT_0 = 100,
  _1_fac__branchIfTrue$expr_STA_0$label_LAB_0 = 154,
  _1_fac__Le_int_int2int$right_STA_0$result_STA_0$left_STA_1 = 136,
  _1_fac__Mult_int_int2int$right_STA_0$result_STA_0$left_STA_1 = 190,
  _1_fac__store_void_star$left_STA_0$right_STA_1 = 163,
  _1_fac__PlusA_int_int2int$right_STA_0$result_STA_0$left_STA_1 = 7,
  _1_fac__store_int$left_STA_0$right_STA_1 = 1,
  _1_fac__call$func_LIT_0 = 64
"""

instructionArray = """
_1_fac__constant_int$result_STA_0$value_LIT_0, (unsigned char)1, (unsigned char)0, (unsigned char)0,
                                        (unsigned char)0, _1_fac__local$result_STA_0$value_LIT_0, (unsigned char)4, (unsigned char)0,
                                        (unsigned char)0, (unsigned char)0, _1_fac__store_int$left_STA_0$right_STA_1, _1_fac__constant_int$result_STA_0$value_LIT_0,
                                        (unsigned char)2, (unsigned char)0, (unsigned char)0, (unsigned char)0,
                                        _1_fac__local$result_STA_0$value_LIT_0, (unsigned char)8, (unsigned char)0, (unsigned char)0,
                                        (unsigned char)0, _1_fac__store_int$left_STA_0$right_STA_1, _1_fac__goto$label_LAB_0, (unsigned char)4,
                                        (unsigned char)0, (unsigned char)0, (unsigned char)0, _1_fac__local$result_STA_0$value_LIT_0,
                                        (unsigned char)8, (unsigned char)0, (unsigned char)0, (unsigned char)0,
                                        _1_fac__load_int$left_STA_0$result_STA_0, _1_fac__formal$result_STA_0$value_LIT_0, (unsigned char)0, (unsigned char)0,
                                        (unsigned char)0, (unsigned char)0, _1_fac__load_int$left_STA_0$result_STA_0, _1_fac__Le_int_int2int$right_STA_0$result_STA_0$left_STA_1,
                                        _1_fac__branchIfTrue$expr_STA_0$label_LAB_0, (unsigned char)14, (unsigned char)0, (unsigned char)0,
                                        (unsigned char)0, _1_fac__goto$label_LAB_0, (unsigned char)4, (unsigned char)0,
                                        (unsigned char)0, (unsigned char)0, _1_fac__goto$label_LAB_0, (unsigned char)51,
                                        (unsigned char)0, (unsigned char)0, (unsigned char)0, _1_fac__local$result_STA_0$value_LIT_0,
                                        (unsigned char)4, (unsigned char)0, (unsigned char)0, (unsigned char)0,
                                        _1_fac__load_int$left_STA_0$result_STA_0, _1_fac__local$result_STA_0$value_LIT_0, (unsigned char)8, (unsigned char)0,
                                        (unsigned char)0, (unsigned char)0, _1_fac__load_int$left_STA_0$result_STA_0, _1_fac__Mult_int_int2int$right_STA_0$result_STA_0$left_STA_1,
                                        _1_fac__local$result_STA_0$value_LIT_0, (unsigned char)4, (unsigned char)0, (unsigned char)0,
                                        (unsigned char)0, _1_fac__store_int$left_STA_0$right_STA_1, _1_fac__local$result_STA_0$value_LIT_0, (unsigned char)8,
                                        (unsigned char)0, (unsigned char)0, (unsigned char)0, _1_fac__load_int$left_STA_0$result_STA_0,
                                        _1_fac__constant_int$result_STA_0$value_LIT_0, (unsigned char)1, (unsigned char)0, (unsigned char)0,
                                        (unsigned char)0, _1_fac__PlusA_int_int2int$right_STA_0$result_STA_0$left_STA_1, _1_fac__local$result_STA_0$value_LIT_0, (unsigned char)8,
                                        (unsigned char)0, (unsigned char)0, (unsigned char)0, _1_fac__store_int$left_STA_0$right_STA_1,
                                        _1_fac__goto$label_LAB_0, (unsigned char)190, (unsigned char)255, (unsigned char)255,
                                        (unsigned char)255, _1_fac__goto$label_LAB_0, (unsigned char)185, (unsigned char)255,
                                        (unsigned char)255, (unsigned char)255, _1_fac__string$result_STA_0$value_LIT_0, (unsigned char)0,
                                        (unsigned char)0, (unsigned char)0, (unsigned char)0, _1_fac__convert_void_star2void_star$left_STA_0$result_STA_0,
                                        _1_fac__local$result_STA_0$value_LIT_0, (unsigned char)16, (unsigned char)0, (unsigned char)0,
                                        (unsigned char)0, _1_fac__store_void_star$left_STA_0$right_STA_1, _1_fac__formal$result_STA_0$value_LIT_0, (unsigned char)0,
                                        (unsigned char)0, (unsigned char)0, (unsigned char)0, _1_fac__load_int$left_STA_0$result_STA_0,
                                        _1_fac__local$result_STA_0$value_LIT_0, (unsigned char)24, (unsigned char)0, (unsigned char)0,
                                        (unsigned char)0, _1_fac__store_int$left_STA_0$right_STA_1, _1_fac__local$result_STA_0$value_LIT_0, (unsigned char)4,
                                        (unsigned char)0, (unsigned char)0, (unsigned char)0, _1_fac__load_int$left_STA_0$result_STA_0,
                                        _1_fac__local$result_STA_0$value_LIT_0, (unsigned char)28, (unsigned char)0, (unsigned char)0,
                                        (unsigned char)0, _1_fac__store_int$left_STA_0$right_STA_1, _1_fac__call$func_LIT_0, (unsigned char)1,
                                        (unsigned char)0, (unsigned char)0, (unsigned char)0, _1_fac__goto$label_LAB_0,
                                        (unsigned char)4, (unsigned char)0, (unsigned char)0, (unsigned char)0,
                                        _1_fac__returnVoid$
"""

# Convert opcodes string to a dict
opcodesSplit = opcodesStruct.replace(",", "").split("\n")
opcodesDict = {}
for line in opcodesSplit:
    if line == '':
        continue
    equalsSplit = line.split(" = ")
    opcodesDict[equalsSplit[0].strip()] = hex(int(equalsSplit[1]))

# Convert instruction array to csv
csvFile = open("fac_instructions.csv", "w")
csvFile.write("#, Opcode, Operand Bytes, Explanation\n")
instructions = instructionArray.replace("(unsigned char)", "").replace("\n", "").split(", ")
instructionCount = 0
for instruction in instructions:
    if instruction.strip() == '':
        continue
    if instruction.strip() in opcodesDict:
        if instructionCount != 0:
            csvFile.write(",  \n")
        instructionCount += 1
        csvFile.write(str(instructionCount) + "," + opcodesDict[instruction.strip()].upper() + ",")
        
    else:
        csvFile.write(hex(int(instruction.strip())).upper() + " ") # operand

csvFile.close()