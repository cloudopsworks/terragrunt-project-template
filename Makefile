##
# (c) 2023 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#
TRONADOR_AUTO_INIT := true

-include $(shell curl -sSL -o .tronador "https://cowk.io/acc"; echo .tronador)

BOILERPLATE := $(INSTALL_DIR)/boilerplate

clean::
	@find . -name 'tfplan.out' -type f -exec rm -rf {} \;
	@find . -name '*.tfplan' -type f -exec rm -rf {} \;
	@find . -name '.terraform.lock.hcl' -type f -exec rm -rf {} \;
	@find . -name '.terragrunt-cache' -type d -exec rm -rf {} \;

init: packages/install/boilerplate
	@$(BOILERPLATE) --template-url .boilerplate --output-folder .
