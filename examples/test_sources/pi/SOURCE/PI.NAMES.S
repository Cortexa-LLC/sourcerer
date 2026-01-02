*-----------------------------
* Source file for linking name
* file for the PI modules.
*-----------------------------

          TYP $F0        ;CMD file (Any type is
                         ; allowed by the linker,
                         ; so this opcode is NOT
                         ; required in a names file.)

* Each file name MUST end with a BRK:

          STR "/MERLIN/PI/START"00
          STR "/MERLIN/PI/MAIN"00
          STR "/MERLIN/PI/LOOK"00
          STR "/MERLIN/PI/DIV"00
          STR "/MERLIN/PI/ADD"00
          BRK            ;Must end file with
                         ; a second BRK.
          SAVE /MERLIN/PI/NAMES
