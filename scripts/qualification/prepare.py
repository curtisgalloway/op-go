#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Create a Go overlay for instrumented qualification; never edit CLI source."""

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    output = Path(sys.argv[1]).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    replacements = {}
    changes = {
        "internal/store/worker.go": [
            (
                "inputRead.Close()\n\toutputWrite.Close()",
                'qual.Child("worker-started", cmd.Process.Pid)\n'
                "\tinputRead.Close()\n\toutputWrite.Close()",
            ),
            (
                "result, err := workerOperation(ctx, req)",
                'qual.Hit("worker-request-" + req.Operation)\n'
                "\tresult, err := workerOperation(ctx, req)\n"
                '\tqual.Hit("worker-result-" + req.Operation)',
            ),
        ],
        "internal/launch/sdk.go": [
            (
                "client, err := onepassword.NewClient",
                'qual.Hit("sdk-initialization")\n'
                "\tclient, err := onepassword.NewClient",
            ),
            (
                "return &sdkResolver{client}, nil",
                'qual.Hit("sdk-initialized")\n\treturn &sdkResolver{client}, nil',
            ),
            (
                "value, err := resolveSDKReference",
                'qual.Hit("sdk-resolution")\n\tvalue, err := resolveSDKReference',
            ),
        ],
        "internal/launch/exec_unix.go": [
            (
                "return unix.Exec(path, args, env)",
                'qual.Hit("launcher-before-exec")\n\treturn unix.Exec(path, args, env)',
            ),
        ],
    }
    for relative, edits in changes.items():
        path = ROOT / relative
        source = path.read_text()
        source = source.replace(
            "import (",
            "import (\nqual "
            '"github.com/curtisgalloway/op-go/scripts/qualification/checkpoint"',
            1,
        )
        for old, new in edits:
            if source.count(old) != 1:
                raise RuntimeError("Instrumentation anchor is not unique: " + relative)
            source = source.replace(old, new)
        if relative == "internal/launch/sdk.go":
            source = source.replace("import (", 'import (\n"os"', 1)
            source = source.replace(
                'qual.Hit("sdk-initialization")',
                'if os.Getenv("OP_GO_QUALIFICATION_SYNTHETIC") == "1" {'
                " return qualificationResolver{}, nil }; "
                'qual.Hit("sdk-initialization")',
                1,
            )
            source += (
                "\ntype qualificationResolver struct{}\n"
                "func (qualificationResolver) Resolve(context.Context, string) "
                '(string, error) { return "op-go-test-value", nil }\n'
            )
        target = output / path.name
        target.write_text(source)
        replacements[str(path)] = str(target)
    (output / "overlay.json").write_text(json.dumps({"Replace": replacements}))


if __name__ == "__main__":
    main()
