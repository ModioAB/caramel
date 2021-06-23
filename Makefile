#Python3 and virtual environment
VENV := $(shell mktemp -d /tmp/caramel-test.XXXXX)
PYTHON3 := $(VENV)/bin/python3

# PIDs of background processes
SERVER_PID := $(VENV)/server.pid
AUTOSIGN_PID := $(VENV)/autosign.pid

# Database and CA cert and key for caramel server to use
DB_FILE := $(VENV)/caramel.sqlite
CA_CERT := $(VENV)/caramel.ca.cert
CA_KEY := $(VENV)/caramel.ca.key

# client.crt will be generated if the server correctly gives our stored CSR back
CLIENT_CERT := $(VENV)/client.crt

# If caramel_tool exists in the venv caramel has been installed
CARAMEL_TOOL := $(VENV)/bin/caramel_tool

# Terminal formatting
BOLD := tput bold
PASS := $(BOLD); tput setaf 2
FAIL := $(BOLD); tput setaf 1
LINE := echo "---------------------------------------"
RESET_TERM := tput op; tput sgr0
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
.PHONEY: venv-install
venv-install: $(CARAMEL_TOOL)
$(CARAMEL_TOOL): $(PYTHON3) setup.py
	@$(BOLD); echo "Install caramel and its dependencies in venv: $(VENV)";\
	$(BLR);
	$(VENV)/bin/pip3 install -e .
	@$(BLR)

# Create a sqlite-db configured for use with caramel
$(DB_FILE): $(CARAMEL_TOOL)
	@$(BOLD); echo "Create a new DB at $(DB_FILE)";\
	$(BLR);
	$(VENV)/bin/caramel_initialize_db
	@$(BLR)

# Generate a new CA cert and key pair
$(CA_CERT): $(CARAMEL_TOOL)
	@$(BOLD); echo "Generate new CA cert and key with tests/ca_test_input.txt";\
	$(BLR)
	$(VENV)/bin/caramel_ca < tests/ca_test_input.txt
	@$(BLR)

# Start caramel using pserve in the background, save PID to SERVER_PID
$(SERVER_PID): $(CA_CERT) $(DB_FILE)
	@ $(BOLD); echo "Start new caramel server in the background, sleep 2s to \
	give it time to start";\
	$(BLR)
	chmod +x scripts/caramel_launcher.sh
	setsid ./scripts/caramel_launcher.sh $(VENV)/bin/pserve >/dev/null 2>&1 < /dev/null & \
	echo $$! > $(SERVER_PID)
	sleep 2s
	@$(BLR)

# Start caramel_autosign in the background, save PID to AUTOSIGN_PID
$(AUTOSIGN_PID): $(CARAMEL_TOOL) $(CA_CERT) $(DB_FILE)
	@$(BOLD);echo "Start new caramel_autosign in the background";\
	$(BLR)
	setsid $(VENV)/bin/caramel_autosign >/dev/null 2>&1 < /dev/null &\
	echo $$! > $(AUTOSIGN_PID)
	@$(BLR)

# Try to upload a CSR to a caramel server and then confirm our CSR was stored
$(CLIENT_CERT): $(SERVER_PID) $(AUTOSIGN_PID)
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
.PHONEY: systest
systest: export CARAMEL_INI = development.ini
systest: export CARAMEL_DBURL = sqlite:///$(DB_FILE)
systest: export CARAMEL_CA_CERT = $(CA_CERT)
systest: export CARAMEL_CA_KEY = $(CA_KEY)
systest: export CARAMEL_CA = 127.0.0.1:6543
systest: export CARAMEL_LOG_LEVEL = ERROR
systest: $(CLIENT_CERT)
	@kill $(shell cat $(SERVER_PID));\
	if [ $$? -eq 0 ]; then \
		$(PASS); $(LINE);\
		echo "Caramel server started and terminated successfully";\
	else \
		$(FAIL); $(LINE);\
		echo "System test failed: Caramel server exited before termination with\
		 exit code: $$?";\
		exit 1;\
	fi;
	@$(BLR)

	@kill $(shell cat $(AUTOSIGN_PID));\
	if [ $$? -eq 0 ]; then \
		$(PASS); $(LINE);\
		echo "Autosign server started and terminated successfully";\
	else \
		$(FAIL); $(LINE);\
		echo "System test failed: Autosign server exited before terminated with\
		 exit code: $$?";\
		exit 1;\
	fi;
	@$(BLR)

	@if [ -f $(CLIENT_CERT) ]; then \
		$(PASS); $(LINE);\
		echo "System test passed: Caramel successfully registered our CSR";\
	else \
		$(FAIL); $(LINE);\
		echo "System test failed: Something went wrong when communicating with \
		the server";\
		exit 1;\
	fi;\
	$(BLR)


# Removes the virtual environment created via this makefile,
# NOTE: this will remove all previous virtual environments
.PHONEY: clean
clean:
	@echo "Removing local test virtual environments"; $(BLR)
	rm -rf /tmp/caramel-test.*
	@$(BLR)
