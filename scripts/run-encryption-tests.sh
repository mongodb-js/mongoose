#!/usr/bin/env bash

# sets up mongodb cluster and encryption configuration, adds relevant variables to the environment, and runs encryption tests

export CWD=$(pwd);

# set up mongodb cluster and encryption configuration if the data/ folder does not exist
# note: for tooling, cluster set-up and configuration look into the 'scripts/configure-cluster-with-encryption.sh' script

if [ -d "data" ]; then
  cd data
else
  source $CWD/scripts/configure-cluster-with-encryption.sh
fi

# extracts MONGOOSE_TEST_URI and CRYPT_SHARED_LIB_PATH from .yml file into environment variables for this test run
read -r -d '' SOURCE_SCRIPT << EOM
const fs = require('fs');
const file = fs.readFileSync('mo-expansion.yml', { encoding: 'utf-8' })
	.trim().split('\\n');
const regex = /^(?<key>.*): "(?<value>.*)"$/;
const variables = file.map(
	(line) => regex.exec(line.trim()).groups
).map(
	({key, value}) => \`export \${key}='\${value}'\`
).join('\n');

process.stdout.write(variables);
process.stdout.write('\n');
EOM

node --eval "$SOURCE_SCRIPT" | tee expansions.sh
source expansions.sh

export MONGOOSE_TEST_URI=$MONGODB_URI

# run encryption tests
cd ..
npx mocha --exit ./test/encryption/*.test.js
