SUBDIR=tool

.PHONY: all clean $(SUBDIR)

all: $(SUBDIR)

$(SUBDIR):
	@echo "===>" $@
	$(MAKE) -C $@ DESTDIR=$(DESTDIR) $(MAKECMDGOALS)
	@echo "<===" $@

clean: $(SUBDIR)
