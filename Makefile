ifdef DEBUG
CFLAGS = -g -DDEBUG
endif

prog = ipxbox
src = $(wildcard *.c)
obj = $(src:.c=.o)
dep = $(obj:.o=.dep)

$(prog): $(obj)

-include $(dep)

%.o: %.c
	$(CC) $(CFLAGS) -c -MMD -MF $(@:.o=.dep) -o $@ $<

clean:
	$(RM) $(obj) $(prog) $(dep)

.PHONY: clean
