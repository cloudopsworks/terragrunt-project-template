##
# (c) 2023 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#
TRONADOR_AUTO_INIT := true

-include $(shell curl -sSL -o .tronador "https://cowk.io/acc"; echo .tronador)

BOILERPLATE := $(INSTALL_PATH)/boilerplate
ifneq (,$(wildcard .inputs))
    PARAMS1 := --var-file .inputs
endif
ifneq (,$(wildcard .inputs_mod))
	PARAMS2 := --var-file .inputs_mod
endif
ifneq (,$(wildcard .github/.inputs_cicd))
	PARAMS3 := --var-file .github/.inputs_cicd
endif

clean::
	@find . -name 'tfplan.out' -type f -exec rm -rf {} \;
	@find . -name '*.tfplan' -type f -exec rm -rf {} \;
	@find . -name '.terraform.lock.hcl' -type f -exec rm -rf {} \;
	@find . -name '.terragrunt-cache' -type d -exec rm -rf {} \;

init/project: packages/install/boilerplate
	@$(BOILERPLATE) --template-url .boilerplate/main --output-folder . $(PARAMS1) $(PARAMS2) $(PARAMS3) --disable-dependency-prompt --var iac_project=$(basename $(pwd))
