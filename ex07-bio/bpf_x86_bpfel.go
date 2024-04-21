// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfInfoT struct {
	Pid    uint32
	Rwflag int32
	Major  int32
	Minor  int32
	Name   [16]int8
}

type bpfStartReqT struct {
	Ts      uint64
	DataLen uint64
}

type bpfValT struct {
	Bytes uint64
	Us    uint64
	Io    uint32
	_     [4]byte
}

type bpfWhoT struct {
	Pid  uint32
	Name [16]int8
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	BlkAccountIoDone  *ebpf.ProgramSpec `ebpf:"blk_account_io_done"`
	BlkAccountIoStart *ebpf.ProgramSpec `ebpf:"blk_account_io_start"`
	BlkMqStartRequest *ebpf.ProgramSpec `ebpf:"blk_mq_start_request"`
	BlockIoDone       *ebpf.ProgramSpec `ebpf:"block_io_done"`
	BlockIoStart      *ebpf.ProgramSpec `ebpf:"block_io_start"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	Counts   *ebpf.MapSpec `ebpf:"counts"`
	Start    *ebpf.MapSpec `ebpf:"start"`
	Whobyreq *ebpf.MapSpec `ebpf:"whobyreq"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	Counts   *ebpf.Map `ebpf:"counts"`
	Start    *ebpf.Map `ebpf:"start"`
	Whobyreq *ebpf.Map `ebpf:"whobyreq"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.Counts,
		m.Start,
		m.Whobyreq,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	BlkAccountIoDone  *ebpf.Program `ebpf:"blk_account_io_done"`
	BlkAccountIoStart *ebpf.Program `ebpf:"blk_account_io_start"`
	BlkMqStartRequest *ebpf.Program `ebpf:"blk_mq_start_request"`
	BlockIoDone       *ebpf.Program `ebpf:"block_io_done"`
	BlockIoStart      *ebpf.Program `ebpf:"block_io_start"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.BlkAccountIoDone,
		p.BlkAccountIoStart,
		p.BlkMqStartRequest,
		p.BlockIoDone,
		p.BlockIoStart,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_x86_bpfel.o
var _BpfBytes []byte