# Vectors

`shares.json`, `bricks.json`, `records.json` and `types.json` are those files of `vectors/` of the AXT
0.2.0 release (https://github.com/paxel/axt/releases/tag/v0.2.0), unchanged, under CC0-1.0
as all vectors of AXT are. `test/proposals_test.dart` plays the owner and proposer sessions
of `shares.json`, and `test/shared_value_test.dart` its `shared_value` vectors;
`test/bricks_test.dart` and `test/records_vectors_test.dart` answer every
vector of `bricks.json` and `records.json`; `test/examples_test.dart` reads the example records
of `types.json` with the classes of `package:axt_protocol/examples.dart`. The conformance job
runs every vector of the release.
