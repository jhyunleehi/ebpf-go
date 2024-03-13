// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfArg struct {
	Ts    uint64
	Flags uint64
	Src   uint64
	Dest  uint64
	Fs    uint64
	Data  uint64
	Op    uint32
	_     [4]byte
}

type bpfEvent struct {
	Delta uint64
	Flags uint64
	Pid   uint32
	Tid   uint32
	MntNs uint32
	Ret   int32
	Comm  [16]int8
	Fs    [8]int8
	Src   [4096]int8
	Dest  [4096]int8
	Data  [512]int8
	Op    uint32
	_     [4]byte
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
	MountEntry *ebpf.ProgramSpec `ebpf:"mount_entry"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	Args   *ebpf.MapSpec `ebpf:"args"`
	Events *ebpf.MapSpec `ebpf:"events"`
	Heap   *ebpf.MapSpec `ebpf:"heap"`
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
	Args   *ebpf.Map `ebpf:"args"`
	Events *ebpf.Map `ebpf:"events"`
	Heap   *ebpf.Map `ebpf:"heap"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.Args,
		m.Events,
		m.Heap,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	MountEntry *ebpf.Program `ebpf:"mount_entry"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.MountEntry,
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
//go:embed bpf_bpfel.o
var _BpfBytes []byte
