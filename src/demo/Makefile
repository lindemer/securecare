.PHONY: app est flash clean

flash:
	$(MAKE) -C boot mbr
	$(MAKE) -C boot flash
	$(MAKE) -C app flash

app:
	$(MAKE) -C boot mbr
	$(MAKE) -C boot flash
	$(MAKE) -C app flash

est:
	$(MAKE) -C boot mbr
	$(MAKE) -C boot flash
	$(MAKE) -C eapp flash

clean:
	$(MAKE) -C boot clean
	$(MAKE) -C eapp clean
	$(MAKE) -C app clean
