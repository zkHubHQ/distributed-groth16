pragma circom 2.1.6;

template MillionConstraints() {
    signal input in;
    signal intermediate[999990];
    signal output out;

    intermediate[0] <== in + 1;

    // Create a chain of a million constraints
    for (var i = 1; i < 999990; i++) {
        intermediate[i] <== intermediate[i-1] + 1;
    }

    out <== intermediate[999989] + 1;
}

component main = MillionConstraints();
