set -ex
trap "exit" INT TERM
trap "kill 0" EXIT

# cargo build --example d_sha256
# BIN=../target/debug/examples/d_sha256

cargo build --release --example d_sha256 --features parallel
BIN=../target/release/examples/d_sha256

l=2
t=1
m=32768
n=8

for n_parties in $n
do
  PROCS=()
  for i in $(seq 0 $(($n_parties - 1)))
  do
    #$BIN $i ./network-address/4 &
    if [ $i == 0 ]
    then
      RUST_BACKTRACE=0 RUST_LOG=d_sha256 $BIN $i ../network-address/$n_parties $l $t $m &
      pid=$!
      PROCS[$i]=$pid
    else
      RUST_LOG=d_sha256 $BIN $i ../network-address/$n_parties $l $t $m > /dev/null &
      pid=$!
      PROCS[$i]=$pid
    fi
  done
  
  for pid in ${PROCS[@]}
  do
    wait $pid || { echo "Process $pid exited with an error status"; exit 1; }
  done
done

echo done
