#Python3 and virtual environment
VENV := $(shell mktemp -d /tmp/caramel-test.XXXXX)
PYTHON3 := $(VENV)/bin/python3

# PIDs of background processes saved at VENV/[PROGRAM]-[test].pid
SERVER := $(VENV)/server
AUTOSIGN := $(VENV)/autosign

# Database and CA cert and key for caramel server to use
DB_FILE := $(VENV)/caramel.sqlite
CA_CERT := $(VENV)/caramel.ca.cert
CA_KEY := $(VENV)/caramel.ca.key
DB_URL := sqlite:///$(DB_FILE)

# client.crt will be generated if the server correctly gives our stored CSR back
CLIENT_CERT := $(VENV)/client.crt

# If caramel_tool exists in the venv caramel has been installed
CARAMEL_TOOL := $(VENV)/bin/caramel_tool

# Terminal formatting
BOLD := printf "\033[1m"
PASS := $(BOLD); printf "\033[32m"
FAIL := $(BOLD); printf "\033[31m"
LINE := $(BOLD); echo "---------------------------------------"
RESET_TERM := printf "\033[0m"
BLR := $(BOLD); $(LINE); $(RESET_TERM) #Bold Line, Reset formatting

#Check for python3 install and virtual environment
$(PYTHON3):
	@if [ -z python3 ]; then \
		$(FAIL);\
		echo "Python 3 could not be found.";\
		$(RESET_TERM);\
		exit 2; \
	fi
	@$(BOLD); echo "Create a new venv for testing at $(VENV)";\
	$(BLR);
	python3 -m venv $(VENV)
	@$(BLR)


#Install the project via setup.py
.PHONY: venv-install
venv-install: $(CARAMEL_TOOL)
$(CARAMEL_TOOL): $(PYTHON3) setup.py
	@$(BOLD); echo "Install caramel and its dependencies in venv: $(VENV)";\
	$(BLR);
	$(VENV)/bin/pip3 install -e .
	@$(BLR)

# Create a sqlite-db configured for use with caramel
.PHONY: gen-db%
gen-db%: $(CARAMEL_TOOL)
	@$(BOLD); echo "Create a new DB at $(DB_FILE)";\
	$(BLR);
	$(VENV)/bin/caramel_initialize_db
	@$(BLR)

# Generate a new CA cert and key pair
.PHONY: ca-cert%
ca-cert%: $(CARAMEL_TOOL)
	@$(BOLD); echo "Generate new CA cert and key with tests/ca_test_input.txt";\
	$(BLR)
	$(VENV)/bin/caramel_ca < tests/ca_test_input.txt
	@$(BLR)

# Start caramel using pserve in the background, save PID to SERVER
$(SERVER)-env.pid: ca-cert-env gen-db-env
	@ $(BOLD); echo "Start new caramel server in the background, sleep 2s to \
	give it time to start";\
	$(BLR)
	chmod +x scripts/caramel_launcher.sh
	setsid ./scripts/caramel_launcher.sh $(VENV)/bin/pserve >/dev/null 2>&1 < /dev/null & \
	echo $$! > $(SERVER)-env.pid
	sleep 2s
	@$(BLR)

# Start caramel using pserve in the background, save PID to SERVER
$(SERVER)-in%.pid: ca-cert-in% gen-db-in%
	@ $(BOLD); echo "Start new caramel server in the background, sleep 2s to \
	give it time to start";\
	$(BLR)
	setsid $(VENV)/bin/pserve $(CARAMEL_COMMAND_LINE) >/dev/null 2>&1 < /dev/null & \
	echo $$! > $(SERVER)-in$*.pid
	sleep 2s
	@$(BLR)

# Start caramel_autosign in the background, save PID to ENV_AUTOSIGN
$(AUTOSIGN)%.pid: $(CARAMEL_TOOL) ca-cert% gen-db%
	@$(BOLD);echo "Start new caramel_autosign in the background";\
	$(BLR)
	setsid $(VENV)/bin/caramel_autosign $(CARAMEL_COMMAND_LINE) >/dev/null 2>&1 < /dev/null &\
	echo $$! > $(AUTOSIGN)$*.pid
	@$(BLR)

# Try to upload a CSR to a caramel server and then confirm our CSR was stored
.PHONY: client-run%
client-run%: $(SERVER)%.pid $(AUTOSIGN)%.pid
	@ $(BOLD); echo "Use client-example.sh to upload our CSR, wait for it to \
	get processed, then call it again to confirm the server stored our CSR";\
	$(BLR)
	chmod +x scripts/client-example.sh
	./scripts/client-example.sh $(VENV)
	sleep 2s
	./scripts/client-example.sh $(VENV)
	@$(BLR)

# Basic tests that caramel can be installed and run with test data,
# using environment variables for config
.PHONY: systest-env
systest-env: export CARAMEL_COMMAND_LINE =
systest-env: export CARAMEL_DBURL = $(DB_URL)
systest-env: export CARAMEL_CA_CERT = $(CA_CERT)
systest-env: export CARAMEL_CA_KEY = $(CA_KEY)
systest-env: export CARAMEL_HOST = 127.0.0.1
systest-env: export CARAMEL_PORT = 6543
systest-env: export CARAMEL_LOG_LEVEL = ERROR
systest-%: client-run-%
	@kill $(shell cat $(SERVER)-$*.pid);\
	if [ $$? -eq 0 ]; then \
		$(PASS); $(LINE);\
		echo "Caramel server started and terminated successfully";\
	else \
		$(FAIL); $(LINE);\
		echo "$@ failed: Caramel server exited before termination with\
		 exit code: $$?";\
		exit 1;\
	fi;
	@$(BLR)

	@kill $(shell cat $(AUTOSIGN)-$*.pid);\
	if [ $$? -eq 0 ]; then \
		$(PASS); $(LINE);\
		echo "Autosign server started and terminated successfully";\
	else \
		$(FAIL); $(LINE);\
		echo "$@ failed: Autosign server exited before terminated with\
		 exit code: $$?";\
		exit 1;\
	fi;
	@$(BLR)

	@if [ -f $(CLIENT_CERT) ]; then \
		$(PASS); $(LINE);\
		echo "$@ passed: Caramel successfully registered our CSR";\
	else \
		$(FAIL); $(LINE);\
		echo "$@ failed: Something went wrong when communicating with \
		the server";\
		exit 1;\
	fi;\
	$(BLR)
	@ echo "Move test data after successfull run"
	mkdir $(VENV)/$@
	mv -t $(VENV)/$@ $(CLIENT_CERT) $(DB_FILE) $(CA_CERT) $(CA_KEY) 


# Removes the virtual environment created via this makefile,
# NOTE: this will remove all previous virtual environments
.PHONY: clean
clean:
	@echo "Removing local test virtual environment"; $(BLR)
	rm -rf $(VENV)
	@$(BLR)
