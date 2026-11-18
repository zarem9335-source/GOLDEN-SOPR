// Package fec: forward error correction for GOLDEN SOPR (UDP/KCP paths).
// Reed-Solomon (8 data + 2 parity shards by default) with a simple XOR
// parity fallback when the RS encoder cannot be built or a shard is lost
// in a way RS cannot repair.
package fec

import (
	"bytes"
	"errors"

	"github.com/klauspost/reedsolomon"
)

// Defaults used by the KCP transport.
const (
	DefaultDataShards   = 8
	DefaultParityShards = 2
)

// Encode splits data into dataShards data shards plus parityShards parity
// shards. All shards have equal length; the original length is returned
// separately so Decode can trim padding.
func Encode(data []byte, dataShards, parityShards int) (shards [][]byte, origLen int, err error) {
	if dataShards < 1 || parityShards < 1 {
		return nil, 0, errors.New("fec: shard counts must be >= 1")
	}
	if len(data) == 0 {
		return nil, 0, errors.New("fec: empty data")
	}
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, 0, err
	}
	shardSize := (len(data) + dataShards - 1) / dataShards
	shards = make([][]byte, dataShards+parityShards)
	for i := range shards {
		shards[i] = make([]byte, shardSize)
	}
	for i, b := range data {
		shards[i/shardSize][i%shardSize] = b
	}
	if err := enc.Encode(shards); err != nil {
		return nil, 0, err
	}
	return shards, len(data), nil
}

// EncodeDefault is Encode with the GOLDEN SOPR defaults (8+2).
func EncodeDefault(data []byte) ([][]byte, int, error) {
	return Encode(data, DefaultDataShards, DefaultParityShards)
}

// Decode reconstructs data from shards (nil entries = lost shards).
// origLen trims the padding added by Encode.
func Decode(shards [][]byte, dataShards, parityShards, origLen int) ([]byte, error) {
	if len(shards) != dataShards+parityShards {
		return nil, errors.New("fec: wrong shard count")
	}
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, err
	}
	if err := enc.Reconstruct(shards); err != nil {
		return nil, err
	}
	ok, err := enc.Verify(shards)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("fec: verification failed after reconstruction")
	}
	var buf bytes.Buffer
	for _, sh := range shards[:dataShards] {
		buf.Write(sh)
	}
	out := buf.Bytes()
	if origLen < len(out) {
		out = out[:origLen]
	}
	return out, nil
}

// DecodeDefault is Decode with the GOLDEN SOPR defaults (8+2).
func DecodeDefault(shards [][]byte, origLen int) ([]byte, error) {
	return Decode(shards, DefaultDataShards, DefaultParityShards, origLen)
}

// XORParity returns a single parity shard: byte-wise XOR of all shards.
// Fallback when Reed-Solomon is unavailable; recovers any single lost shard.
func XORParity(shards [][]byte) []byte {
	if len(shards) == 0 {
		return nil
	}
	par := make([]byte, len(shards[0]))
	for _, sh := range shards {
		for i := range par {
			if i < len(sh) {
				par[i] ^= sh[i]
			}
		}
	}
	return par
}

// XORRecover rebuilds the shard at missingIdx from the other shards plus parity.
func XORRecover(shards [][]byte, parity []byte, missingIdx int) []byte {
	if missingIdx < 0 || missingIdx >= len(shards) {
		return nil
	}
	out := make([]byte, len(parity))
	copy(out, parity)
	for i, sh := range shards {
		if i == missingIdx {
			continue
		}
		for j := range out {
			if j < len(sh) {
				out[j] ^= sh[j]
			}
		}
	}
	return out
}
