// Copyright 2022 Google LLC
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

import Foundation

struct DifferentialHashPostProcessor: FuzzingPostProcessor {
    func process(_ program: Program, for fuzzer: Fuzzer) -> Program {
        // Only one call to fuzzilli_hash() per program.
        if program.code.containsDifferential() {
            return program
        }

        // We cannot access the actual state of the active programBuilder.
        // `fuzzer.makeBuilder()` will create a fresh instance without state.
        // Result is that calls such as `b.hasVisibleVariables` will always be
        // false. To solve this, we need to rebuild the program state by copying
        // over each instruction with `b.append()` step by step.
        //
        // Doing so and then calling `b.calculateDifferentialHash()` will result
        // in the `DifferentialHash` always being the last instruction, instead
        // of being inserted at random places though. That is because the
        // PostProcessor will be invoked right before executing the program, no
        // other code generation will happen.
        //
        // To fix this, choose a random `insertionPoint`, copy the program up to
        // this point, then do `b.calculateDifferentialHash()`, and continue to
        // copy the rest of the program.
        //
        // It may be possible that the random point will be at a position w/o any
        // visible variables (for instance at index 0), so repeat up to 5 times.
        var currentAttempt = 0
        while currentAttempt < 5 {
            let b = fuzzer.makeBuilder(forMutating: program)

            let insertionPoint = Int.random(in: 0..<program.code.count)
            for i in 0..<insertionPoint {
                b.append(program.code[i])
            }
            
            if b.hasVisibleVariables {
                b.calculateDifferentialHash(ofVariable: b.randomVariable())
                for i in insertionPoint..<program.code.count {
                    b.append(program.code[i])
                }
                return b.finalize()
            }
            
            currentAttempt += 1
        }

        return program
    }
}

/// Purely generative fuzzing engine, mostly used for initial corpus generation when starting without an existing corpus.
public class GenerativeEngine: FuzzEngine {
    /// Approximate number of instructions to generate in additional to any prefix code.
    private let numInstructionsToGenerate = 10

    public init() {
        super.init(name: "GenerativeEngine")
        super.registerPostProcessor(DifferentialHashPostProcessor())
    }

    /// Perform one round of fuzzing: simply generate a new program and execute it
    public override func fuzzOne(_ group: DispatchGroup) {
        let b = fuzzer.makeBuilder()

        // Start by building a prefix that creates some variables (of known types) that the following CodeGenerators can then make use of.
        b.buildPrefix()
        // Then generate the actual code.
        b.build(n: numInstructionsToGenerate, by: .generating)
        let program = b.finalize()

        let _ = execute(program)
    }
}
