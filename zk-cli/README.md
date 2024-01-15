# CLI Tool for offloading zk proof generation

The current implementation supports the following operations:

- `save` - save the r1cs and witness to a file, and generate the proving and verification keys

```bash
zk-cli save <CIRCUIT_NAME> <R1CS_FILEPATH> <WITNESS_GENERATOR_FILEPATH>
```

- `prove` - generate the proof from the r1cs and witness

```bash
zk-cli prove <CIRCUIT_NAME> <R1CS_FILEPATH> <WITNESS_FILEPATH>
```

- `verify` - verify the proof with the proving and verification keys