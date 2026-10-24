// Runs before every test file: keep tests away from the real ~/.locked and the Keychain.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.LOCKED_HOME = mkdtempSync(join(tmpdir(), "locked-test-"));
process.env.LOCKED_KEYSTORE = "file";
process.env.LOCKED_KEYCHAIN_SERVICE = "locked-test";
