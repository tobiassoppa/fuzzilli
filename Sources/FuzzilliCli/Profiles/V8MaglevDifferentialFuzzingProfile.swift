// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Fuzzilli

fileprivate let ForceJITCompilationThroughLoopGenerator = CodeGenerator("ForceJITCompilationThroughLoopGenerator", inputs: .required(.function())) { b, f in
    assert(b.type(of: f).Is(.function()))
    let arguments = b.randomArguments(forCalling: f)

    // Default for Maglev is n=400, set to a lower value with --invocation-count-for-maglev=95
    b.buildRepeatLoop(n: 100) { _ in
        b.callFunction(f, withArgs: arguments)
    }
}

fileprivate let ForceMaglevCompilationGenerator = CodeGenerator("ForceMaglevCompilationGenerator", inputs: .required(.function())) { b, f in
    assert(b.type(of: f).Is(.function()))
    let arguments = b.randomArguments(forCalling: f)

    b.callFunction(f, withArgs: arguments)

    b.eval("%PrepareFunctionForOptimization(%@)", with: [f]);

    b.callFunction(f, withArgs: arguments)
    b.callFunction(f, withArgs: arguments)

    b.eval("%OptimizeMaglevOnNextCall(%@)", with: [f]);

    b.callFunction(f, withArgs: arguments)
}

fileprivate let WorkerGenerator = RecursiveCodeGenerator("WorkerGenerator") { b in
    let workerSignature = Signature(withParameterCount: Int.random(in: 0...3))

    // TODO(cffsmith): currently Fuzzilli does not know that this code is sent
    // to another worker as a string. This has the consequence that we might
    // use variables inside the worker that are defined in a different scope
    // and as such they are not accessible / undefined. To fix this we should
    // define an Operation attribute that tells Fuzzilli to ignore variables
    // defined in outer scopes.
    let workerFunction = b.buildPlainFunction(with: .parameters(workerSignature.parameters)) { args in
        let this = b.loadThis()

        // Generate a random onmessage handler for incoming messages.
        let onmessageFunction = b.buildPlainFunction(with: .parameters(n: 1)) { args in
            b.buildRecursive(block: 1, of: 2)
        }
        b.setProperty("onmessage", of: this, to: onmessageFunction)

        b.buildRecursive(block: 2, of: 2)
    }
    let workerConstructor = b.loadBuiltin("Worker")

    let functionString = b.loadString("function")
    let argumentsArray = b.createArray(with: b.randomArguments(forCalling: workerFunction))

    let configObject = b.createObject(with: ["type": functionString, "arguments": argumentsArray])

    let worker = b.construct(workerConstructor, withArgs: [workerFunction, configObject])
    // Fuzzilli can now use the worker.
}

// Insert random GC calls throughout our code.
fileprivate let GcGenerator = CodeGenerator("GcGenerator") { b in
    let gc = b.loadBuiltin("gc")

    // Do minor GCs more frequently.
    let type = b.loadString(probability(0.25) ? "major" : "minor")
    // If the execution type is 'async', gc() returns a Promise, we currently
    // do not really handle other than typing the return of gc to .undefined |
    // .jsPromise. One could either chain a .then or create two wrapper
    // functions that are differently typed such that fuzzilli always knows
    // what the type of the return value is.
    let execution = b.loadString(probability(0.5) ? "sync" : "async")
    b.callFunction(gc, withArgs: [b.createObject(with: ["type": type, "execution": execution])])
}

fileprivate let WasmStructGenerator = CodeGenerator("WasmStructGenerator") { b in
    b.eval("%WasmStruct()", hasOutput: true);
}

fileprivate let WasmArrayGenerator = CodeGenerator("WasmArrayGenerator") { b in
    b.eval("%WasmArray()", hasOutput: true);
}

// TODO(tobias@soppa.me): Prefer variables that are inside of functions, methods etc, not top level vars.
fileprivate let DifferentialHashGenerator = CodeGenerator("DifferentialHashGenerator") { b in
        b.calculateDifferentialHash(ofVariable: b.randomVariable());
}

let v8MaglevDifferentialFuzzingProfile = Profile(
    processArgs: { randomize in
        var args = [
            "--expose-gc",
            "--omit-quit",
            "--allow-natives-syntax",
            "--fuzzing",
            "--jit-fuzzing",
            "--future",
            "--harmony",
            "--js-staging",
            "--wasm-staging",

            "--predictable",
            // Suppress certain unspecified behaviors to ease correctness fuzzing:
            // Abort program when the stack overflows or a string exceeds maximum
            // length (as opposed to throwing RangeError). Use a fixed suppression
            // string for error messages.
            "--correctness-fuzzer-suppressions",
            "--invocation-count-for-maglev=95",
        ]

        guard randomize else { return args }

        //
        // Future features that should sometimes be enabled.
        //
        if probability(0.5) {
            // A (fixed) random seed can make crashes (and the engine in general) more deterministic.
            let seed = Int32.random(in: Int32.min...Int32.max)
            args.append("--random-seed=\(seed)")
        }

        if probability(0.25) {
            args.append("--minor-ms")
        }

        if probability(0.25) {
            args.append("--shared-string-table")
        }

        if probability(0.1) {
            args.append("--harmony-struct")
        }

        if probability(0.1) {
            args.append("--efficiency-mode")
        }

        if probability(0.1) {
            args.append("--battery-saver-mode")
        }

        //
        // Sometimes enable additional verification/stressing logic (which may be fairly expensive).
        //
        if probability(0.1) {
            args.append("--verify-heap")
        }

        if probability(0.1) {
            args.append("--assert-types")
        }

        if probability(0.1) {
            args.append("--stress-ic")
        }

        //
        // More exotic configuration changes.
        //
        if probability(0.05) {
            if probability(0.5) { args.append("--stress-gc-during-compilation") }
            if probability(0.5) { args.append("--lazy-new-space-shrinking") }
            if probability(0.5) { args.append("--const-tracking-let") }
            if probability(0.5) { args.append("--stress-wasm-memory-moving") }
            if probability(0.5) { args.append("--stress-background-compile") }
            if probability(0.5) { args.append("--parallel-compile-tasks-for-lazy") }
            if probability(0.5) { args.append("--parallel-compile-tasks-for-eager-toplevel") }

            args.append(probability(0.5) ? "--always-osr" : "--no-always-osr")
            args.append(probability(0.5) ? "--concurrent-osr" : "--no-concurrent-osr")
            args.append(probability(0.5) ? "--force-slow-path" : "--no-force-slow-path")

            // Maglev related flags
            args.append(probability(0.5) ? "--maglev-inline-api-calls" : "--no-maglev-inline-api-calls")
            if probability(0.5) { args.append("--maglev-extend-properties-backing-store") }
        }

        return args
    },

    // We typically fuzz without any sanitizer instrumentation, but if any sanitizers are active, "abort_on_error=1" must probably be set so that sanitizer errors can be detected.
    processEnv: [:],

    maxExecsBeforeRespawn: 1000,

    timeout: 500,

    codePrefix: """
                """,

    codeSuffix: """
                """,

    ecmaVersion: ECMAScriptVersion.es6,

    startupTests: [
        // Check that the fuzzilli integration is available.
        ("fuzzilli('FUZZILLI_PRINT', 'test')", .shouldSucceed),

        // Check that common crash types are detected.
        // IMMEDIATE_CRASH()
        ("fuzzilli('FUZZILLI_CRASH', 0)", .shouldCrash),
        // CHECK failure
        ("fuzzilli('FUZZILLI_CRASH', 1)", .shouldCrash),
        // DCHECK failure
        ("fuzzilli('FUZZILLI_CRASH', 2)", .shouldCrash),
        // Wild-write
        ("fuzzilli('FUZZILLI_CRASH', 3)", .shouldCrash),
        // Check that DEBUG is defined.
        ("fuzzilli('FUZZILLI_CRASH', 8)", .shouldCrash),

        // TODO we could try to check that OOM crashes are ignored here ( with.shouldNotCrash).
    ],

    differentialCrashingFalsePositives: ["Aborting on "],

    additionalCodeGenerators: [
        (ForceJITCompilationThroughLoopGenerator,  25),
        (ForceMaglevCompilationGenerator,          25),

        (WorkerGenerator,                         10),
        (GcGenerator,                             10),

        // (WasmStructGenerator,                     15),
        // (WasmArrayGenerator,                      15),

        (DifferentialHashGenerator,               80),
    ],

    additionalProgramTemplates: WeightedList<ProgramTemplate>([]),

    disabledCodeGenerators: [],

    disabledMutators: [],

    additionalBuiltins: [
        "gc"                                            : .function([] => (.undefined | .jsPromise)),
        "d8"                                            : .object(withProperties: ["test"]),
        "Worker"                                        : .constructor([.anything, .object()] => .object(withMethods: ["postMessage","getMessage"])),
    ],

    additionalObjectGroups: [],

    // TODO(tobias@soppa.me): Add.
    optionalPostProcessor: nil
)
