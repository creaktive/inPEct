NAME = inPEct
OBJS = $(NAME).obj
DEF  = $(NAME).def
RES  = $(NAME).res

!if $d(DEBUG)
TASMDEBUG=/zi
LINKDEBUG=/v
!else
TASMDEBUG=
LINKDEBUG=
!endif

!if $d(MAKEDIR)
IMPORT=$(MAKEDIR)\..\lib\import32
!else
IMPORT=import32
!endif


$(NAME).EXE: $(OBJS) $(DEF)
  brc32 -r $(NAME)
  tlink32 /V4.0 /x /Tpe /aa /c $(LINKDEBUG) $(OBJS),$(NAME),, $(IMPORT), $(DEF), $(RES)

.ASM.OBJ:
  tasm32 $(TASMDEBUG) /ml /m2 $&.asm
