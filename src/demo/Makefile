.PHONY: app eapp mapp flash clean

flash:
	$(MAKE) -C boot mbr
	$(MAKE) -C boot flash
	$(MAKE) -C app flash

app:
	$(MAKE) -C boot mbr
	$(MAKE) -C boot flash
	$(MAKE) -C app flash

eapp:
	$(MAKE) -C boot mbr
	$(MAKE) -C boot flash
	$(MAKE) -C eapp flash


mapp:
	$(MAKE) -C boot mbr
	$(MAKE) -C boot flash
	$(MAKE) -C mapp flash

clean:
	$(MAKE) -C boot clean
	$(MAKE) -C eapp clean
	$(MAKE) -C app clean
	$(MAKE) -C mapp clean
