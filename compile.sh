#!/bin/bash

set -e

javac -d build src/main/*/*.java
(cd build; jar cvf sourceMap.jar *)
