# Install the nginx data-placement (nginxdp) components.
#
# By default, scripts are installed into /usr/local/sbin,
# and a template file is installed into /usr/local/share/dataplacement.
# Configuration is installed to /etc/nginxdp.ini; an existing
# config file will not be overwritten; instead, /etc/nginxdp.ini.new
# is created.
#
# The "dirs" target creates the directories needed for the data placement
# server to work (using the default config) under DATA_DIR
# (default /srv/dataplacement).
#
# Usage (paths can be staged with DESTDIR, relocated with PREFIX):
#   make                          show this help
#   make install                  install services, template, and config
#   make install DESTDIR=/tmp/s   stage a tree for packaging
#   make dirs                     create the nginx data/log directories
#   make uninstall                remove installed files

.DEFAULT_GOAL := help

DESTDIR ?=
PREFIX ?= /usr/local

# Where the components land.
SBINDIR ?= $(PREFIX)/sbin
TEMPLATE_DIR ?= $(PREFIX)/share/dataplacement
SYSCONFDIR ?= /etc

# Runtime paths used by the `dirs` target (see nginxdp.ini).
DATA_DIR ?= /srv/dataplacement
LOG_DIR ?= /var/log/dataplacement
CONDOR_MAPFILE_DIR ?= /etc/condor/user-mapfiles
NGINX_USER ?= nginx
NGINX_GROUP ?= nginx

INSTALL ?= install
PYTHON ?= python3

# The services; launched as `python3 <path>`, kept executable for convenience.
SBIN_EXEC := dataauth.py uploadmover.py nginxdp.py
# Shared config loader, imported by the services rather than run.
SBIN_DATA := nginxdp_config.py
TEMPLATE := nginx-dataplacement.conf.template
CONF := nginxdp.ini

CONFS := $(SBIN_EXEC) $(SBIN_DATA)

.PHONY: help all install dirs uninstall

all: install

help:
	@sed -n '2,18p' $(firstword $(MAKEFILE_LIST))

install:
	@$(INSTALL) -d -m 0755 $(DESTDIR)$(SBINDIR) $(DESTDIR)$(TEMPLATE_DIR) $(DESTDIR)$(SYSCONFDIR)
	@for f in $(SBIN_EXEC); do \
	    echo "  INSTALL sbin/$$f -> $(SBINDIR)/$$f"; \
	    $(INSTALL) -m 0755 "sbin/$$f" "$(DESTDIR)$(SBINDIR)/$$f" || exit 1; \
	done
	@for f in $(SBIN_DATA); do \
	    echo "  INSTALL sbin/$$f -> $(SBINDIR)/$$f"; \
	    $(INSTALL) -m 0644 "sbin/$$f" "$(DESTDIR)$(SBINDIR)/$$f" || exit 1; \
	done
	@echo "  INSTALL $(TEMPLATE) -> $(TEMPLATE_DIR)/$(notdir $(TEMPLATE))"
	@$(INSTALL) -m 0644 $(TEMPLATE) "$(DESTDIR)$(TEMPLATE_DIR)/$(notdir $(TEMPLATE))"
	@target='$(DESTDIR)$(SYSCONFDIR)/$(notdir $(CONF))'; \
	if [ -f "$$target" ] && ! cmp -s $(CONF) "$$target"; then \
	    echo "  INSTALL $(CONF) -> $(SYSCONFDIR)/$(notdir $(CONF)).new (existing config kept)"; \
	    $(INSTALL) -m 0644 $(CONF) "$$target.new"; \
	else \
	    echo "  INSTALL $(CONF) -> $(SYSCONFDIR)/$(notdir $(CONF))"; \
	    $(INSTALL) -m 0644 $(CONF) "$$target"; \
	fi

# Nginx runs as a non-root user, so its directories and log files must exist and
# belong to it before the first start.
dirs:
	@$(INSTALL) -d -m 0755 $(DESTDIR)$(CONDOR_MAPFILE_DIR)
	@$(INSTALL) -o $(NGINX_USER) -g $(NGINX_GROUP) -d -m 0755 \
	    $(DESTDIR)$(DATA_DIR) \
	    $(DESTDIR)$(DATA_DIR)/files \
	    $(DESTDIR)$(DATA_DIR)/files_upload \
	    $(DESTDIR)$(DATA_DIR)/files_upload_tmp
	@$(INSTALL) -o $(NGINX_USER) -g root -d -m 0751 $(DESTDIR)$(LOG_DIR)
	@for f in access error; do \
	    touch "$(DESTDIR)$(LOG_DIR)/$$f.log" || exit 1; \
	    chown $(NGINX_USER):root "$(DESTDIR)$(LOG_DIR)/$$f.log" || exit 1; \
	done
	@if [ -d $(DESTDIR)/var/log/nginx ]; then \
	    echo "  CHOWN /var/log/nginx -> $(NGINX_USER)"; \
	    chown $(NGINX_USER):$(NGINX_GROUP) $(DESTDIR)/var/log/nginx || exit 1; \
	fi

uninstall:
	@rm -f $(addprefix $(DESTDIR)$(SBINDIR)/,$(CONFS))
	@rm -f $(DESTDIR)$(TEMPLATE_DIR)/$(notdir $(TEMPLATE))
	@rm -f $(DESTDIR)$(SYSCONFDIR)/$(notdir $(CONF)) $(DESTDIR)$(SYSCONFDIR)/$(notdir $(CONF)).new
