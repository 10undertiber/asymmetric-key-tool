#!/bin/sh
set -eu

if ! command -v native-image >/dev/null 2>&1; then
  echo "native-image is required for the Native smoke test" >&2
  exit 2
fi

mvn -q -DskipTests test-compile
native-image -cp "target/test-classes:target/classes" \
  com.tenut.asymmetrickeytool.NativeSmokeMain target/native-smoke
target/native-smoke
