.PHONY: all build test clean run

BUILD_DIR := build

all: build

build:
	cmake -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_DIR) -j$$(nproc)

debug:
	cmake -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Debug
	cmake --build $(BUILD_DIR) -j$$(nproc)

test:
	cd $(BUILD_DIR) && ctest --output-on-failure

run:
	@echo "Running requires root:"
	sudo $(BUILD_DIR)/ebpf-monitor

run-json:
	sudo $(BUILD_DIR)/ebpf-monitor --json

clean:
	rm -rf $(BUILD_DIR)
