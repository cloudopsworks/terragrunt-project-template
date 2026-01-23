##
# (c) 2021-2025
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#
TRONADOR_AUTO_INIT := true
GITVERSION ?= $(INSTALL_PATH)/gitversion

-include $(shell curl -sSL -o .tronador "https://cowk.io/acc"; echo .tronador)

BOILERPLATE := $(INSTALL_PATH)/boilerplate
ifneq (,$(wildcard .inputs))
    PARAMS1 := --var-file=.inputs
endif
ifneq (,$(wildcard .inputs_mod))
	PARAMS2 := --var-file=.inputs_mod
endif
ifneq (,$(wildcard .inputs_state))
	PARAMS4 := --var-file=.inputs_state
endif
ifneq (,$(wildcard .cloudopsworks/.inputs_cicd))
	PARAMS3 := --var-file=.cloudopsworks/.inputs_cicd
endif
USER_VARS ?=

## Lint terragrunt modules
lint:
	@$(SELF) terragrunt/install terragrunt/get-modules terragrunt/get-plugins terragrunt/lint terragrunt/validate

get_version: packages/install/gitversion
	$(call assert-set,GITVERSION)
	$(eval VER_NUM := v$(shell $(GITVERSION) -output json -showvariable MajorMinorPatch))
	$(eval VER_MAJOR := $(shell echo $(VER_NUM) | cut -f1 -d.))
	$(eval VER_MINOR := $(shell echo $(VER_NUM) | cut -f2 -d.))
	$(eval VER_PATCH := $(shell echo $(VER_NUM) | cut -f3 -d.))

co_master:
	git checkout master

tag_local: co_master get_version
	git tag -f $(VER_MAJOR).$(VER_MINOR)
	git tag -f $(VER_MAJOR)

## Tag the current version
tag:: tag_local
	git push origin -f $(VER_MAJOR).$(VER_MINOR)
	git push origin -f $(VER_MAJOR)
	git checkout develop

## Cleanup terragrunt caches from the Project
clean::
	@find . -name 'tfplan.out' -type f -exec rm -rf {} \;
	@find . -name '*.tfplan' -type f -exec rm -rf {} \;
	@find . -name '.terraform.lock.hcl' -type f -exec rm -rf {} \;
	@find . -name '.terragrunt-cache' -type d -exec rm -rf {} \;

## Initialize the project with boilerplate
init/project:: packages/install/boilerplate
	@$(BOILERPLATE) --template-url .cloudopsworks/boilerplate/main --output-folder . $(USER_VARS) $(PARAMS1) $(PARAMS2) $(PARAMS3) $(PARAMS4) --var=iac_project=$(shell basename $$(pwd)) --disable-dependency-prompt

## Cleanup project boilerplate cache
clean/project::
	@rm -f .inputs .inputs_mod .cloudopsworks/.inputs_cicd