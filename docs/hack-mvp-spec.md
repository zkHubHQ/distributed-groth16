# Most basic MVP for running Collaborative Proofs

## Standalone non-MPC proof generation

1. Have a field in the input request with privacy = false
2. Pass circuit id, check and cache the crs params in the backend server as a flat file for now
3. Pass circuit's r1cs, wasm, input json file
4. Return a json containing the proof, public params, time taken in response body

## MPC based proof generation

1. Have a field in the input request with privacy = true
2. Pass circuit id, check and cache the crs params in the backend server as a flat file for now
3. Pass circuit's r1cs, wasm, input json, file, party id, pss params
4. Return a json containing the proof, public params, time taken in response body

## Proof verification, common for both MPC and non-MPC

1. Pass circuit id, check and cache the crs params in the backend server as a flat file for now
2. Also have another option to pass the verification key (optional)
3. Pass the proof, public json file
4. Return result of the verification, along with time taken

## CLI toolkit for interacting with the services

### Non-MPC proof

1. dacc prove command with privacy set to false, have the paths to inputs and outputs

### MPC proof

1. dacc prove command with privacy set to false, have the paths to inputs and outputs
2. Does the work of witness computation and sends the shares to individual endpoints via rest api calls
3. Listens to the response from all nodes, uses the output from the first response, deserialize the json output, and store into a file

### Verification

1. dacc verify command with privacy set to false, have the paths to inputs and outputs

### Circuit init

1. Save the circuit to a file, and create the crs params/shares for the circuit