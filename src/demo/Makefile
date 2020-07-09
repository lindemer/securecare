default: flash

.PHONY: flash clean

flash:
	$(MAKE) -C boot mbr
	$(MAKE) -C boot flash
	$(MAKE) -C app flash

clean:
	$(MAKE) -C boot clean
	$(MAKE) -C app clean
